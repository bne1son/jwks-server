mod key;

use std::{
    net::{TcpStream, TcpListener},
    io::{BufReader, prelude::*},
    time::{SystemTime, UNIX_EPOCH}
};
use serde::Serialize;
use key::Key;

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    use_: String,
    alg: String,
    n: String,
    e: String,
}

fn main() {
    let key = Key::new(
        "active-key".to_string(),
        2_000_000_000,
    );

    let expired_key = Key::new(
        "expired-key".to_string(),
        1_000_000_000,
    );

    let socket = TcpListener::bind("127.0.0.1:8080");
    for stream in socket.unwrap().incoming() {
        let stream = stream.unwrap();
        handle_connection(stream, &key, &expired_key);
    }
}

fn handle_connection(mut stream: TcpStream, key: &Key, expired_key: &Key) {
    let http_request = get_http_request(&stream);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("Active expired: {}", key.is_expired(now));
    println!("Expired expired: {}", expired_key.is_expired(now));
    if http_request[0].starts_with("GET /.well-known/jwks.json") {
        println!("JWKS endpoint");
        let mut jwks: Vec<Jwk> = Vec::new();
        if !key.is_expired(now) {
            let jwk = Jwk {
                kty: "RSA".to_string(),
                kid: key.kid().to_string(),
                use_: "sig".to_string(),
                alg: "RS256".to_string(),
                n: key.modulus(),
                e: key.exponent(),
            };
            jwks.push(jwk);
        }
        let jwks = Jwks {
            keys: jwks,
        };

        let body = serde_json::to_string(&jwks).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {}", body
        );
        stream.write_all(response.as_bytes()).unwrap();
    } else if http_request[0].starts_with("POST /auth") {
        println!("Auth endpoint");
        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    } else {
        println!("404");
        let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
}

// Returns a stringified http request
fn get_http_request(stream: &TcpStream) -> Vec<String> {
    let reader = BufReader::new(stream);
    let http_request: Vec<String> = {
        reader
            .lines()
            .map(|result| result.unwrap())
            .take_while(|line| !line.is_empty())
            .collect()
    };
    return http_request;
}