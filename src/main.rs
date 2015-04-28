#![feature(plugin)]
#![plugin(docopt_macros)]

extern crate crypto;
extern crate rustc_serialize;
extern crate rand;
extern crate time;
extern crate docopt;

use std::ascii::AsciiExt;
use crypto::mac::Mac;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use rustc_serialize::hex::ToHex;

fn sign (msg: String, key: String) -> String {
    let msg_bytes = msg.into_bytes();
    let key_bytes = key.into_bytes();

    let mut hmac = Hmac::new(Sha1::new(), &key_bytes);
    hmac.input(&msg_bytes);
    let result = hmac.result();
    result.code().to_hex()
}

static NONCE_CHARS: &'static str = "abc123def456ghi789jk0_";
fn nonce() -> String {
    let mut nonce = String::new();
    for _ in 0..7 {
        let idx = rand::random::<usize>() % NONCE_CHARS.len();
        nonce.push(NONCE_CHARS.chars().nth(idx).unwrap());
    }
    nonce
}

fn timestamp() -> i64 {
    let now = time::now_utc();
    now.to_timespec().sec
}

#[derive(Debug)]
struct Signature {
    appid: String,
    clientid: String,
    convid: String,
    action: String,
    members: String,
    timestamp: i64,
    nonce: String,
    signature: String
}

fn sort_members(members: String) -> String {
    let mut m: Vec<&str> = members.split(":").collect();
    m.sort();
    m.connect(":")
}

fn gen_signature_message(action: String, appid: String, clientid: String,
                         convid: String, members: String,
                         t: i64, n: String) -> String {
    let normalized_action = action.to_ascii_lowercase();
    let mut buf = Vec::<String>::new();
    buf.push(appid);
    buf.push(clientid);
    match normalized_action.as_ref() {
        "add" | "remove" => {
            buf.push(convid);
        },
        _ => {}
    }

    if normalized_action == "open" {
        buf.push("".to_string());
    } else {
        buf.push(sort_members(members));
    }
    buf.push(t.to_string());
    buf.push(n);

    match normalized_action.as_ref() {
        "add"  => {
            buf.push("invite".to_string());
        },
        "remove" => {
            buf.push("kick".to_string());
        },
        _ => {}
    }

    buf.connect(":")
}

docopt!(Args derive Debug, "
Usage: leancloud-rtm-signature-tool <action> [options]
       leancloud-rtm-signature-tool --help

Options:
  -h, --help         Show this message.
  --appid <arg>      Set application id.
  --clientid <arg>   Set client id.
  --convid <arg>     Set conversation id.
  --members <arg>    Set members list.
  --masterkey <arg>  Provide master key for signing.
");

fn main() {
    let args: Args = Args::docopt().decode().unwrap_or_else(|e| e.exit());
    let ts = timestamp();
    let n = nonce();
    let msg = gen_signature_message(args.arg_action.clone(),
                                    args.flag_appid.clone(),
                                    args.flag_clientid.clone(),
                                    args.flag_convid.clone(),
                                    args.flag_members.clone(),
                                    ts.clone(),
                                    n.clone());
    let sig = sign(msg, args.flag_masterkey);
    let result = Signature {
        appid: args.flag_appid,
        clientid: args.flag_clientid,
        convid: args.flag_convid,
        action: args.arg_action,
        members: args.flag_members,
        timestamp: ts,
        nonce: n,
        signature: sig
    };
    println!("{:?}", result);
}
