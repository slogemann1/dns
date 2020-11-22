extern crate rusqlite;

mod dns_request;

use std::net::{ TcpListener, TcpStream };
use std::thread;
use std::io::{ Read, Write };

use dns_request::{ DnsResponse, DnsAnswer, DnsRecordType };

fn main() {
    let server = TcpListener::bind("0.0.0.0:53").expect("Server failed to bind");

    println!("Server Started");
    for client in server.incoming() {
        println!("New Client");
        if let Ok(client) = client {
            thread::spawn(move || {
                handle_client(client)
            });
        }
        else {
            println!("Failed to accept client");
        }
    }
}

fn handle_client(mut client: TcpStream) {
    println!("Client Connected");

    let mut buffer: [u8; 2048] = [0; 2048];
    let num_bytes = match client.read(&mut buffer) {
        Ok(val) => val,
        Err(_) => {
            return;
        }
    };

    let query;
    if num_bytes > 2 {
        query = match dns_request::parse_query(&buffer[0..num_bytes].to_vec()) {
            Some(val) => val,
            None => {
                return;
            }
        };
    }
    else {
        return;
    }

    //Check query bytes
    let mut file = std::fs::OpenOptions::new()
    .write(true)
    .truncate(true)
    .create(true)
    .open("./data/request.bin").unwrap();
    file.write_all(&buffer[0..num_bytes]);

    let answer = DnsAnswer::default()
    .name(query.questions[0].qname.clone())
    .ttl(100)
    .record(DnsRecordType::new_A("192.168.0.1"));

    let response = DnsResponse::default()
    .id(query.header.id)
    .answer(&answer);

    println!("Response: {:#?}", response.build());

    client.write(&response.build());
}