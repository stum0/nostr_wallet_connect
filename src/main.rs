use std::env;
use std::str::FromStr;

use email_address::EmailAddress;
use nostr::nips::nip47::NostrWalletConnectURI;
use serde::de::Error;
use serde_json::Value;
use url::Url;

use nostr::prelude::{decrypt, encrypt};
use nostr::secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use nostr::{
    ClientMessage, Event, EventId, Filter, Kind, RelayMessage, Result, SubscriptionId, Tag,
    Timestamp,
};
use serde::{Deserialize, Serialize};
use tungstenite::{connect, Message as WsMessage};

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub invoice: String,
}

#[derive(Serialize, Deserialize)]
pub struct PayInvoiceRequest {
    pub method: String,
    pub params: Params,
}

impl PayInvoiceRequest {
    pub fn new(invoice: String) -> Self {
        PayInvoiceRequest {
            method: "pay_invoice".to_string(),
            params: Params { invoice },
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Please provide an ln_address as the first argument.");
    }

    let ln_address = &args[1];
    let amount_in_sats: i64 = args[2]
        .parse()
        .expect("Invalid amount. Please enter a number.");
    let amount_in_millisats = amount_in_sats * 1000;

    let nwc_uri: String = env::var("NWC_URI").expect("NO NWC_URI ENV_VAR");

    println!("NWC_URI: {}", nwc_uri);

    let uri = Url::parse(&nwc_uri).expect("Failed to parse URL");

    let relay = uri
        .query_pairs()
        .find(|(key, _)| key == "relay")
        .map(|(_, value)| value.into_owned())
        .expect("Failed to get relay");

    let secret = uri
        .query_pairs()
        .find(|(key, _)| key == "secret")
        .map(|(_, value)| value.into_owned())
        .expect("Failed to get secret");

    let lud16 = uri
        .query_pairs()
        .find(|(key, _)| key == "lud16")
        .map(|(_, value)| value.into_owned())
        .expect("Failed to get lud16");

    let public_key = uri.host().unwrap().to_string();

    let nwc_service_pubkey = XOnlyPublicKey::from_str(public_key.as_str()).unwrap();
    let secret = SecretKey::from_str(&secret).unwrap();
    let relay_url = Url::parse(&relay).unwrap();

    let nwc = NostrWalletConnectURI::new(nwc_service_pubkey, relay_url, Some(secret), Some(lud16))
        .unwrap();

    let secp = Secp256k1::new();

    let (mut socket, _response) = connect(Url::parse(&relay)?).expect("Can't connect to relay");

    let nwc_key_pair = KeyPair::from_secret_key(&secp, &nwc.secret);
    let nwc_pubkey = XOnlyPublicKey::from_keypair(&nwc_key_pair);

    //sub
    let id = uuid::Uuid::new_v4();
    let subscribe = ClientMessage::new_req(
        SubscriptionId::new(id.to_string()),
        vec![Filter::new()
            .kind(Kind::WalletConnectResponse)
            .since(Timestamp::now())
            .pubkey(nwc_pubkey.0)],
    );

    println!("Subscribing to relay");
    socket.write_message(WsMessage::Text(subscribe.as_json()))?;

    //pay
    let ln_address = LightningAddress::new(ln_address).unwrap();
    let ln_url = ln_address.lnurlp_url();

    let ln_address_res = reqwest::get(ln_url).await?;

    println!(
        "LN Address Response: {:?} {}",
        ln_address_res.version(),
        ln_address_res.status()
    );

    let body = ln_address_res.text().await?;

    let ln_response: LnService = serde_json::from_str(&body).unwrap();

    println!("callback address {:?}", ln_response.callback);

    let callback = format!("{}?amount={}", ln_response.callback, amount_in_millisats,);

    let invoice_res = reqwest::get(callback).await?;

    println!(
        "Invoice Response: {:?} {}",
        invoice_res.version(),
        invoice_res.status()
    );

    let body = invoice_res.text().await?;

    let value: Value = serde_json::from_str(&body)?;
    let invoice = value["pr"]
        .as_str()
        .ok_or_else(|| serde_json::Error::custom("Missing pr field"))?;

    println!("Invoice: {}", invoice);

    let request = PayInvoiceRequest::new(invoice.to_string());

    let created_at = Timestamp::now();
    let kind = Kind::WalletConnectRequest;

    let tags = vec![Tag::PubKey(nwc_service_pubkey, None)];

    let request_bytes = serde_json::to_vec(&request).unwrap();
    let content = encrypt(&nwc.secret, &nwc_service_pubkey, &request_bytes).unwrap();

    let id = EventId::new(&nwc_pubkey.0, created_at, &kind, &tags, &content);

    let id_bytes = id.as_bytes();
    let sig = Message::from_slice(id_bytes).unwrap();

    let pay_event = Event {
        id,
        kind,
        content,
        pubkey: nwc_pubkey.0,
        created_at,
        tags,
        sig: nwc_key_pair.sign_schnorr(sig),
    };

    let nwc_pay = ClientMessage::new_event(pay_event);

    socket.write_message(WsMessage::Text(nwc_pay.as_json()))?;
    println!("sending invoice to relay");

    loop {
        let msg = socket.read_message().expect("Error reading message");
        let msg_text = msg.to_text().expect("Failed to convert message to text");
        if let Ok(handled_message) = RelayMessage::from_json(msg_text) {
            match handled_message {
                RelayMessage::Empty => {
                    println!("Empty message")
                }
                RelayMessage::Notice { message } => {
                    println!("Got a notice: {}", message);
                }
                RelayMessage::EndOfStoredEvents(_subscription_id) => {
                    println!("Relay signalled End of Stored Events");
                }
                RelayMessage::Ok {
                    event_id,
                    status,
                    message,
                } => {
                    println!("Got OK message: {} - {} - {}", event_id, status, message);
                }
                RelayMessage::Event {
                    event,
                    subscription_id: _,
                } => {
                    let event =
                        decrypt(&nwc_key_pair.secret_key(), &event.pubkey, &event.content).unwrap();

                    //add a match here to handle the different types of events
                    println!("{:#?}", event);
                    return Ok(());
                }
                _ => (),
            }
        } else {
            println!("Received unexpected message: {}", msg_text);
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct LightningAddress {
    value: EmailAddress,
}

impl LightningAddress {
    pub fn new(value: &str) -> Result<Self> {
        EmailAddress::from_str(value)
            .map(|value| LightningAddress { value })
            .map_err(|_| "Invalid email address".into())
    }

    #[inline]
    pub fn lnurlp_url(&self) -> String {
        format!(
            "https://{}/.well-known/lnurlp/{}",
            self.value.domain(),
            self.value.local_part()
        )
    }
}

#[derive(Deserialize, Debug)]
pub struct PayerData {
    pub name: Option<Mandatory>,
    pub identifier: Option<Mandatory>,
}

#[derive(Deserialize, Debug)]
pub struct Mandatory {
    pub mandatory: bool,
}

#[derive(Deserialize, Debug)]
pub struct LnService {
    #[serde(rename = "minSendable")]
    pub min_sendable: u64,
    #[serde(rename = "maxSendable")]
    pub max_sendable: u64,
    #[serde(rename = "commentAllowed")]
    pub comment_allowed: Option<u64>,
    pub tag: String,
    pub metadata: String,
    pub callback: String,
    #[serde(rename = "payerData")]
    pub payer_data: Option<PayerData>,
    pub disposable: Option<bool>,
    #[serde(rename = "allowsNostr")]
    pub allows_nostr: Option<bool>,
    #[serde(rename = "nostrPubkey")]
    pub nostr_pubkey: Option<String>,
}
