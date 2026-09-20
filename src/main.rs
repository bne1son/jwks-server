use std::{
    net::{TcpStream, TcpListener},
    io::{BufReader, prelude::*}
};
use serde::Serialize;

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
    let socket = TcpListener::bind("127.0.0.1:8080");
    for stream in socket.unwrap().incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    let http_request = get_http_request(&stream);
    if http_request[0].starts_with("GET /.well-known/jwks.json") {
        println!("JWKS endpoint");

        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-key".to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            n: "fake-modulus".to_string(),
            e: "AQAB".to_string(),
        };
        let jwks = Jwks {
            keys: vec![jwk],
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

fn get_http_request(stream: &TcpStream) -> Vec<String> {
    let reader = BufReader::new(stream);
    let http_request: Vec<String> = {
        reader
            .lines()
            .map(|result| result.unwrap())
            .take_while(|line| !line.is_empty())
            .collect()
    };
    http_request
}