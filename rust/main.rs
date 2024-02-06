use std::collections::HashMap;
use chrono::Utc;

mod secure;

fn encode_auth_header(username: &str, password: &str) -> String {
    let timestamp = Utc::now().timestamp();
    let signature = secure::calculate_hash(secure::base64_encode(&format!("{}{}{}", username, password, timestamp)));
    let statement = format!("PYS username={},Signature={},timestamp={}", username, signature, timestamp);
    statement
}

fn decode_auth_header(header: &str, password: &str) {
    let parts = header.split(',').collect::<Vec<_>>();
    let part0 = parts.first().unwrap().split('=').collect::<Vec<_>>();
    let part1 = parts.get(1).unwrap().split('=').collect::<Vec<_>>();
    let part2 = parts.last().unwrap().split('=').collect::<Vec<_>>();
    let header_user = part0.get(1).unwrap();
    let header_signature = part1.get(1).unwrap();
    let header_timestamp = part2.get(1).unwrap();
    println!("{}", &header_signature);
    println!("{}", &header_user);
    println!("{}", &header_timestamp);
    let expected_signature = secure::calculate_hash(secure::base64_encode(&format!("{}{}{}", header_user, password, header_timestamp)));
    if expected_signature == *header_signature {
        println!("Signature Authentication Successful")
    } else {
        println!("Signature Authentication Failed")
    }
}

fn main() {
    let username = "foo";
    let password = "bar";
    let header = encode_auth_header(username, password);
    println!("Authentication Header: {}", &header);
    decode_auth_header(&header, password);
    let auth = format!("{}{}", username, password);
    let b64_encoded = secure::base64_encode(&auth);
    let b64_decoded = secure::base64_decode(&b64_encoded);
    println!("B64 encoded: {}", b64_encoded);
    println!("B64 decoded: {}", b64_decoded);
    let hex_encoded = secure::hex_encode(&auth);
    let hex_decoded = secure::hex_decode(&hex_encoded);
    println!("Hex encoded: {}", hex_encoded);
    println!("Hex decoded: {}", hex_decoded);
    let payload = HashMap::from([
        ("username", username),
        ("password", password)
    ]);
    let encrypted = secure::FERNET.encrypt(serde_json::to_string(&payload).unwrap().as_bytes());
    println!("Fernet encrypted: {}", encrypted);
    if let Ok(decrypted) = secure::FERNET.decrypt(&encrypted) {
        let payload: HashMap<String, String> = serde_json::from_str(&String::from_utf8_lossy(&decrypted)).unwrap();
        println!("Fernet decrypted: {:?}", payload);
    }
}
