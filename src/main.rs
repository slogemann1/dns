extern crate rusqlite;

mod dns_request;

use std::net::{ TcpListener, TcpStream, UdpSocket };
use std::thread;
use std::io::{ Read, Write };

use dns_request::{ DnsResponse, DnsAnswer, DnsRecordType, DnsAuthRecord };

fn main() {
    let server_tcp_v4 = TcpListener::bind("0.0.0.0:53").expect("Server failed to bind");
    let server_udp_v4 = UdpSocket::bind("0.0.0.0:53").expect("Server failed to bind");
    let server_tcp_v6 = TcpListener::bind("[::]:53").expect("Server failed to bind");
    let server_udp_v6 = UdpSocket::bind("[::]:53").expect("Server failed to bind");

    thread::spawn(move || {
        println!("Tcp (Ipv4) Server Started");
        for client in server_tcp_v4.incoming() {
            if let Ok(client) = client {
                thread::spawn(move || {
                    handle_tcp_client(client)
                });
            }
            else {
                println!("Failed to accept client (Tcp v4)");
            }
        }
    });

    thread::spawn(move || {
        println!("Tcp (Ipv6) Server Started");
        for client in server_tcp_v6.incoming() {
            if let Ok(client) = client {
                thread::spawn(move || {
                    handle_tcp_client(client)
                });
            }
            else {
                println!("Failed to accept client (Tcp v6)");
            }
        }
    });

    thread::spawn(move || {
        println!("Udp (Ipv4) Server Started");
        handle_udp_server(server_udp_v4);
    });

    println!("Udp (Ipv6) Server Started");
    handle_udp_server(server_udp_v6);
}

fn handle_udp_server(server: UdpSocket) {
    loop {
        let mut buffer: [u8; 2048] = [0; 2048];
        let (num_bytes, client) = match server.recv_from(&mut buffer) {
            Ok(val) => val,
            Err(_) => {
                //println!("Failed to accept client (Udp)");
                continue;
            }
        };

        let server_copy = match server.try_clone() {
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

    let mut response = DnsResponse::default()
    .id(query.header.id)
    .rd(query.header.rd);

    for question in query.questions {
        let mut answer = DnsAnswer::default()
        .name(question.qname.clone())
        .ttl(100);

        if question.qtype == DnsRecordType::A(None) {
            if !query.header.rd {
                let record = DnsAuthRecord::default()
                .mname(vec!(String::from("www"), String::from("shit"), String::from("com")))
                .rname(vec!(String::from("www"), String::from("hello"), String::from("com")));
                answer = answer.record(DnsRecordType::new_SOA(record));

                response = response.add_auth_record(answer);
            }
            else {
                answer = answer.record(DnsRecordType::new_A("13.107.21.200"));
                response = response.add_answer(answer);
            }
        }
        else if question.qtype == DnsRecordType::AAAA(None) {
            if !query.header.rd {
                answer = answer.record(DnsRecordType::new_AAAA("2a02:8108:96c0:19b8:138a:f55e:8212:330b"));
            }
            else {
                answer = answer.record(DnsRecordType::new_AAAA("2a02:8108:96c0:19b8:138a:f55e:8212:330b"));
                response = response.add_answer(answer);
            }
        }
        else if let DnsRecordType::NotImplemented(val) = question.qtype {
            println!("Unimplemented Record Request: {}", val);
        }
        else {
            println!("Unimplemented Record Request: {:#?}", question.qtype);
        }
    }

    Some(response.build(tcp))
}