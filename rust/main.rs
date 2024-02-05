use chrono::Utc;

use crate::secure::base64_encode;

mod secure;

fn encode_auth_header(username: &str, password: &str) -> String {
    let timestamp = Utc::now().timestamp();
    let signature = secure::calculate_hash(base64_encode(&format!("{}{}{}", username, password, timestamp)));
    let statement = format!("PYS username={},Signature={},timestamp={}", username, signature, timestamp);
    statement
}

fn decode_auth_header(header: &str, password: &str) {
    let parts = header.split(",").collect::<Vec<_>>();
    let part0 = parts.first().unwrap().split("=").collect::<Vec<_>>();
    let part1 = parts.get(1).unwrap().split("=").collect::<Vec<_>>();
    let part2 = parts.last().unwrap().split("=").collect::<Vec<_>>();
    let header_user = part0.get(1).unwrap();
    let header_signature = part1.get(1).unwrap();
    let header_timestamp = part2.get(1).unwrap();
    println!("{}", &header_signature);
    println!("{}", &header_user);
    println!("{}", &header_timestamp);
    let expected_signature = secure::calculate_hash(base64_encode(&format!("{}{}{}", header_user, password, header_timestamp)));
    if &expected_signature == *header_signature {
        println!("successful auth")
    } else {
        println!("failed auth")
    }
}

fn main() {
    let username = "foo";
    let password = "bar";
    let header = encode_auth_header(username, password);
    println!("Authentication Header: {}", &header);
    decode_auth_header(&header, password);
    // let encoded = base64_encode(username);
    // let decoded = base64_decode(&encoded);
    // println!("{}", decoded)
}
