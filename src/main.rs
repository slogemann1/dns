extern crate rusqlite;
extern crate reqwest;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

mod dns_request;
mod handle_data;
mod google_dns;
mod database;

use std::net::{ TcpListener, TcpStream, UdpSocket };
use std::thread;
use std::io::{ Read, Write };

fn main() {
    //Startup (Errors can occur here)
    let server_tcp_v4 = TcpListener::bind("0.0.0.0:53").expect("Server failed to bind");
    let server_udp_v4 = UdpSocket::bind("0.0.0.0:53").expect("Server failed to bind");
    let server_tcp_v6 = TcpListener::bind("[::]:53").expect("Server failed to bind");
    let server_udp_v6 = UdpSocket::bind("[::]:53").expect("Server failed to bind");

    database::init_db();
    //No more expects in my code after this point

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
            let bytes = match handle_data::handle_message(buffer[0..num_bytes].to_vec(), false) {
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

    let bytes = match handle_data::handle_message(buffer[0..num_bytes].to_vec(), true) {
        Some(val) => val,
        None => return
    };

    match client.write(&bytes) {
        Ok(_) => return,
        Err(_) => return
    };
}