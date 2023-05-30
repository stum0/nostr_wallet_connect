use std::str::FromStr;

use nostr::prelude::{decrypt, encrypt, hex, FromBech32};
use nostr::secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use nostr::{
    ClientMessage, Event, EventId, Filter, Keys, Kind, RelayMessage, Result, SubscriptionId, Tag,
    Timestamp, Url,
};
use serde::{Deserialize, Serialize};
use tungstenite::{connect, Message as WsMessage};

const WS_ENDPOINT: &str = "wss://relay.getalby.com/v1";

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

fn main() -> Result<()> {
    env_logger::init();

    let secp = Secp256k1::new();

    let (mut socket, _response) =
        connect(Url::parse(WS_ENDPOINT)?).expect("Can't connect to relay");

    //let nostr_keys = Keys::generate();

    let nwc_secret =
        SecretKey::from_str("1b5cd6b8c358900f727afbb53835005daf2182bb7d3f5e9c17135c8d7e5b94f5")
            .unwrap();
    println!("key: {:?}", nwc_secret.display_secret());
    let nwc_key_pair = KeyPair::from_secret_key(&secp, &nwc_secret);
    let nwc_pubkey = XOnlyPublicKey::from_keypair(&nwc_key_pair);
    let nwc_service_pubkey = XOnlyPublicKey::from_str(
        "69effe7b49a6dd5cf525bd0905917a5005ffe480b58eeb8e861418cf3ae760d9",
    )
    .unwrap();

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

    //info
    // let created_at = Timestamp::now();
    // let kind = Kind::WalletConnectInfo;

    // let tags = vec![];

    // let content = "pay_invoice".to_string();

    // let id = EventId::new(&nwc_pubkey.0, created_at, &kind, &tags, &content);

    // let id_bytes = id.as_bytes();
    // let sig = Message::from_slice(id_bytes).unwrap();

    // let event = Event {
    //     id,
    //     kind,
    //     content,
    //     pubkey: nwc_pubkey.0,
    //     created_at,
    //     tags,
    //     sig: nwc_key_pair.sign_schnorr(sig),
    // };

    // let nwc_info = ClientMessage::new_event(event);

    // socket.write_message(WsMessage::Text(nwc_info.as_json()))?;
    // println!("sending info to relay");

    //pay

    let request = PayInvoiceRequest::new("lnbc1u1pj8vmh6pp54z34u28xgyxacpcyt0rm9wlx32symzdnkq53zs2pn36d6d6ayrgqdqqcqpjsp5nj8vfa4pejgsz0ptlk5ezhhppjdhv992pet49m6nafagukwg2s7q9q7sqqqqqqqqqqqqqqqqqqqsqqqqqysgqmqz9gxqyjw5qrzjqwryaup9lh50kkranzgcdnn2fgvx390wgj5jd07rwr3vxeje0glclla0meput24vfyqqqqlgqqqqqeqqjqlmkayjje8npjja2l6gnjec9lj5cszv7s7h26j4uzpd80qtlf2vxpkpyes43xn8nuylmphje0duy5muvllkrps3yv9szehc9fzh06kxgpz9mcxn".to_string());

    let created_at = Timestamp::now();
    let kind = Kind::WalletConnectRequest;

    let tags = vec![Tag::PubKey(nwc_service_pubkey, None)];

    let request_bytes = serde_json::to_vec(&request).unwrap();
    let content = encrypt(&nwc_secret, &nwc_service_pubkey, &request_bytes).unwrap();

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
                    println!("{:#?}", event);
                }
                _ => (),
            }
        } else {
            println!("Received unexpected message: {}", msg_text);
        }
    }
}
