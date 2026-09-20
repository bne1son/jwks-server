mod key;
mod jose;

use std::{
    net::{TcpStream, TcpListener},
    io::{BufReader, prelude::*},
    time::{SystemTime, UNIX_EPOCH}
};
use key::Key;
use jose::{
    Jwk,
    Jwks,
    jwt_create_header,
    jwt_create_payload
};

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

// handles endpoints
fn handle_connection(mut stream: TcpStream, key: &Key, expired_key: &Key) {
    let http_request = get_http_request(&stream);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if http_request[0].starts_with("GET /.well-known/jwks.json") {
        println!("JWKS endpoint");
        let mut jwks: Vec<Jwk> = Vec::new();
        if !key.is_expired(now) {
            let jwk = Jwk::from_key(&key);
            jwks.push(jwk);
        }
        let jwks = Jwks::new(jwks);
        let body = serde_json::to_string(&jwks).unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {}", body
        );
        stream.write_all(response.as_bytes()).unwrap();
    } else if http_request[0].starts_with("POST /auth") {
                let header = jose::jwt_create_header(key);
                let payload = jose::jwt_create_payload(key);
                let encoded_header = jose::to_base64(&header);
                let encoded_payload = jose::to_base64(&payload);
                let header_payload = format!("{}.{}", encoded_header, encoded_payload);
                let signature = key.sign(header_payload.as_bytes());
                let encoded_signature = jose::base64url_bytes(&signature);
                let jwt = format!("{}.{}.{}", encoded_header, encoded_payload, encoded_signature);
                println!("JWT: {}", jwt);

        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    } else {
        println!("404");
        let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
}

// returns a string-by-string vector of http request
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