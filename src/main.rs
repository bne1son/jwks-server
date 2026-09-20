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
    jwt_create_payload,
    to_base64,
    base64url_bytes
};

fn main() {
    // sample key which expires in half hour
    let sample_key = Key::new(
        "active-key".to_string(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 1800,
    );

    // sample key which expired half hour ago
    let sample_expired_key = Key::new(
        "expired-key".to_string(),
        sample_key.expires_at() - 3600
    );

    let socket = TcpListener::bind("127.0.0.1:8080");
    // listen on 127.0.0.1:8080
    for stream in socket.unwrap().incoming() {
        let stream = stream.unwrap();
        handle_connection(
            stream,
            &sample_key,
            &sample_expired_key
        );
    }
}

pub fn handle_connection(mut stream: TcpStream, key: &Key, expired_key: &Key) {
    // splits stream to give to endpoints
    let http_request = get_http_request(&stream);
    let request_line: Vec<&str> = http_request[0]
        .split_whitespace()
        .collect();
    let method = request_line[0];
    let (path, query) = match request_line[1].split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request_line[1], None)
    };
    // for expiration checking
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // handles endpoints
    match (method, path) {
        ("GET", "/.well-known/jwks.json") => {
            println!("JWKS endpoint hit");
            let mut jwks_vec: Vec<Jwk> = Vec::new();
            // check expiration
            if !key.is_expired(now) {
                let jwk = Jwk::from_key(key);
                jwks_vec.push(jwk);
            }
            // create jwks from many jwk
            let jwks = Jwks::new(jwks_vec);
            let body = serde_json::to_string(&jwks).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             \r\n\
             {}", body
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
        ("POST", "/auth") => {
            let auth_key = if query == Some("expired=true") {
                expired_key
            } else {
                key
            };
            let encoded_header = to_base64(
                &jwt_create_header(auth_key)
            );
            let encoded_payload = to_base64(
                &jwt_create_payload(auth_key)
            );
            let header_and_payload = format!(
                "{}.{}",
                encoded_header,
                encoded_payload
            );
            let signature = auth_key.sign(header_and_payload.as_bytes());
            let encoded_signature = base64url_bytes(&signature);
            let jwt = format!(
                "{}.{}.{}",
                encoded_header,
                encoded_payload,
                encoded_signature
            );
            println!("JWT: {}", jwt);
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
            Content-Type: application/json\r\n\
            \r\n\
            {{\"token\":\"{}\"}}",
                jwt
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
        (_, "/.well-known/jwks.json") => {
            let response = "HTTP/1.1 405 METHOD NOT ALLOWED\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        }
        (_, "/auth") => {
            let response = "HTTP/1.1 405 METHOD NOT ALLOWED\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        }
        _ => {
            println!("404");
            let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
        }
    }
}

// returns a string-by-string vector of http request
pub fn get_http_request(stream: &TcpStream) -> Vec<String> {
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


//###################################//
//              Tests                //
//###################################//
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{TcpListener, TcpStream},
        thread,
    };

    fn send_request(request: &str) -> String {
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (stream, _) = socket.accept().unwrap();
            let key = Key::new("active-key".to_string(), 2_000_000_000);
            let expired_key = Key::new("expired-key".to_string(), 1);
            handle_connection(stream, &key, &expired_key);
        });
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        handle.join().unwrap();
        return response;
    }

    #[test]
    fn jwks_returns_200() {
        let response = send_request(
            "GET /.well-known/jwks.json HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
        );
        assert!(response.contains("200 OK"));
    }

    #[test]
    fn auth_returns_200() {
        let response = send_request(
            "POST /auth HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
        );
        assert!(response.contains("200 OK"));
        assert!(response.contains("\"token\""));
    }

    #[test]
    fn expired_auth_returns_200() {
        let response = send_request(
            "POST /auth?expired=true HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
        );
        assert!(response.contains("200 OK"));
        assert!(response.contains("\"token\""));
    }

    #[test]
    fn wrong_method_returns_405() {
        let response = send_request(
            "POST /.well-known/jwks.json HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
        );
        assert!(response.contains("405 METHOD NOT ALLOWED"));
    }

    #[test]
    fn unknown_path_returns_404() {
        let response = send_request(
            "GET /does-not-exist HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n",
        );
        assert!(response.contains("404 NOT FOUND"));
    }
}