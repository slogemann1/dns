extern crate rusqlite;

mod dns_request;

use std::net::{ TcpListener, TcpStream, UdpSocket, SocketAddr };
use std::thread;
use std::io::{ Read, Write };

use dns_request::{ DnsResponse, DnsAnswer, DnsRecordType };

fn main() {
    let server_tcp = TcpListener::bind("0.0.0.0:53").expect("Server failed to bind");
    let server_udp = UdpSocket::bind("0.0.0.0:53").expect("Server failed to bind");

    thread::spawn(move || {
        println!("Tcp Server Started");
        for client in server_tcp.incoming() {
            if let Ok(client) = client {
                thread::spawn(move || {
                    handle_tcp_client(client)
                });
            }
            else {
                println!("Failed to accept client (Tcp)");
            }
        }
    });

    println!("Udp Server Started");
    loop {
        let mut buffer: [u8; 2048] = [0; 2048];
        let (num_bytes, client) = match server_udp.recv_from(&mut buffer) {
            Ok(val) => val,
            Err(_) => {
                println!("Failed to accept client (Udp)");
                continue;
            }
        };

        let server_copy = match server_udp.try_clone() {
            Ok(val) => val,
            Err(_) => continue
        };
        thread::spawn(move || {
            let bytes = match handle_message(buffer[0..num_bytes].to_vec(), false) {
                Some(val) => val,
                None => return
            };

            match server_copy.send_to(&bytes, &client) {
                Ok(_) => (),
                Err(_) => return
            }
        });
    }
}

fn handle_tcp_client(mut client: TcpStream) {
    let mut buffer: [u8; 2048] = [0; 2048];
    let num_bytes = match client.read(&mut buffer) {
        Ok(val) => val,
        Err(_) => {
            return;
        }
    };

    let bytes = match handle_message(buffer[0..num_bytes].to_vec(), true) {
        Some(val) => val,
        None => return
    };

    client.write(&bytes);
}

fn handle_message(buffer: Vec<u8>, tcp: bool) -> Option<Vec<u8>> {
    let query = match dns_request::parse_query(&buffer, tcp) {
        Some(val) => val,
        None => {
            return None;
        }
    };

    let answer = DnsAnswer::default()
    .name(query.questions[0].qname.clone())
    .ttl(100)
    .record(DnsRecordType::new_A("192.168.0.1"));

    let response = DnsResponse::default()
    .id(query.header.id)
    .answer(&answer);

    Some(response.build(tcp))
}