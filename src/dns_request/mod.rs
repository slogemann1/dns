//! # Module for Dns Communication
//! ## For more information see:
//! <https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf> (A brief overview from a client's perspective)\
//! <https://tools.ietf.org/html/rfc1035> (The complete dns specifications)\
//! <https://tools.ietf.org/html/rfc1464> (The specifications for the TXT record format)

use std::convert::TryInto; 

mod structs;
pub use structs::*;

/// Function to parse through a dns query
/// This function takes as input a buffer consisting soley of the bytes required to read the query,
/// and a boolean to signify whether the request was sent by tcp or udp. It returns a DnsQuery on sucess
/// or None on failure
pub fn parse_query(buffer: &Vec<u8>, tcp: bool) -> Option<DnsQuery> {
    let mut buffer = buffer;
    let buffer_temp;
    if tcp {
        buffer_temp = buffer[2..].to_vec(); //Ignore Length bits
        buffer = &buffer_temp;
    }

    let (header, mut buffer) = match parse_header(&buffer) {
        Some(val) => val,
        _ => {
            return None;
        }
    };

    let mut questions: Vec<DnsQuestion> = Vec::new();
    while let Some(ref new_buffer) = buffer {
        let question;
        let ques_buff = match parse_question(&new_buffer) {
            Some(val) => val,
            None => {
                return None;
            }
        };
        question = ques_buff.0;
        buffer = ques_buff.1;
        questions.push(question);
    }

    Some(DnsQuery {
        header: header,
        questions: questions
    })
}

fn parse_header(buffer: &Vec<u8>) -> Option<(DnsHeader, Option<Vec<u8>>)> {
    if buffer.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes(buffer[0..2].try_into().unwrap());
    
    let qr = ((buffer[2] & 0b1_0000_0_0_0) >> 7) != 0;
    let opcode = (buffer[2] & 0b0_1111_0_0_0) >> 3;
    let aa = ((buffer[2] & 0b0_0000_1_0_0) >> 2) != 0;
    let tc = ((buffer[2] & 0b0_0000_0_1_0) >> 1) != 0;
    let rd = (buffer[2] & 0b0_0000_0_0_1) != 0;
    
    let ra = ((buffer[3] & 0b1_000_0000) >> 7) != 0;
    let z = (buffer[3] & 0b0_111_0000) >> 4;
    let rcode = buffer[3] & 0b0_000_1111;
    
    let qd_count = u16::from_be_bytes(buffer[4..6].try_into().unwrap());
    let an_count = u16::from_be_bytes(buffer[6..8].try_into().unwrap());
    let ns_count = u16::from_be_bytes(buffer[8..10].try_into().unwrap());
    let ar_count = u16::from_be_bytes(buffer[10..12].try_into().unwrap());

    let header = DnsHeader {
        id: id,
        qr: qr,
        opcode: opcode,
        aa: aa,
        tc: tc,
        rd: rd,
        ra: ra,
        z: z,
        rcode: DnsResponseCode::from_byte(rcode),
        qd_count: qd_count,
        an_count: an_count,
        ns_count: ns_count,
        ar_count: ar_count
    };

    let remaining;
    if buffer.len() > 12 {
        remaining = Some(buffer[12..].to_vec());
    }
    else {
        remaining = None;
    }

    Some((header, remaining))
}

fn parse_question(buffer: &Vec<u8>) -> Option<(DnsQuestion, Option<Vec<u8>>)> {
    let mut domains: Vec<String> = Vec::new();

    let mut i: usize = 0;
    while i < buffer.len() {
        let mut name = String::new();
        let name_len = buffer[i] as usize;

        let mut j: usize;
        if name_len != 0 {
            i += 1;
            j = 0;
            while j < name_len {
                if i + j >= buffer.len() {
                    return None;
                }
                name.push(buffer[i + j] as char);
                j += 1;
            }
        }
        else {
            i += 1;
            break;
        }
        domains.push(name);
        i = i + j - 1;

        i += 1;
    }

    let qtype;
    let qclass;
    if i + 3 < buffer.len() {
        qtype = u16::from_be_bytes(buffer[i..i+2].try_into().unwrap());
        qclass = u16::from_be_bytes(buffer[i+2..i+4].try_into().unwrap());
    }
    else {
        return None;
    }

    let question = DnsQuestion {
        qname: domains,
        qtype: DnsRecordType::from_byte(qtype as u8),
        qclass: qclass
    };
    let remaining;
    if i + 4 < buffer.len() {
        remaining = Some(buffer[i+4..].to_vec());
    }
    else {
        remaining = None;
    }

    Some((question, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_test() {
        let header = vec!(
            0b0000_0000, //First byte of id
            0b0001_0000, //Second byte of id (16)
            0b0_0001_1_0_1, //qr (0), opcode (1), aa (1), tc (0), rd (1)
            0b1_100_0100, //ra (1), z (4), rcode (4)
            0, 0, //qd_count
            0, 0, //an_count
            0, 0, //ns_count
            0, 0 //ar_count
        );

        let mut expected = DnsHeader::new();
        expected.id = 16;
        expected.opcode = 1;
        expected.aa = true;
        expected.rd = true;
        expected.ra = true;
        expected.z = 4;
        expected.rcode = DnsResponseCode::NotImplemented;

        let (result, more) = parse_header(&header).unwrap();

        assert_eq!(result, expected);
        assert_eq!(more, None);
    }

    #[test]
    fn parse_question_test() {
        let question: Vec<u8> = vec!(
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0111, 101, 120, 97, 109, 112, 108, 101, //length (7), example
            0b0000_0011, 99, 111, 109, //length (3), com
            0b0000_0000, //length (0)
            0, 0b0001_1100, //qtype (28)
            0, 0b0001_0000 //qclass (16) 
        );

        let expected = DnsQuestion {
            qname: vec!(String::from("www"), 
                String::from("example"),
                String::from("com")
            ),
            qtype: DnsRecordType::AAAA(None),
            qclass: 16
        };

        let (result, more) = parse_question(&question).unwrap();

        assert_eq!(result, expected);
        assert_eq!(more, None);
    }

    #[test]
    fn parse_query_test() {
        let query: Vec<u8> = vec!(
            0, 53, //Length of message (53 bytes)
            0b0000_0000, //First byte of id
            0b0001_0000, //Second byte of id (16)
            0b0_0001_1_0_1, //qr (0), opcode (1), aa (1), tc (0), rd (1)
            0b1_100_0100, //ra (1), z (4), rcode (4)
            0, 1, //qd_count
            0, 0, //an_count
            0, 0, //ns_count
            0, 0, //ar_count
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0111, 101, 120, 97, 109, 112, 108, 101, //length (7), example
            0b0000_0011, 99, 111, 109, //length (3), com
            0b0000_0000, //length (0)
            0, 0b0001_1100, //qtype (28)
            0, 0b0001_0000, //qclass (16)
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0110, 103, 111, 111, 103, 108, 101, //length (6), google
            0b0000_0011, 99, 111, 109, //length (3), com
            0b0000_0000, //length (0)
            0, 0b0011_0100, //qtype (52)
            0, 0b0000_0100 //qclass (4)
        );

        let mut expected_header = DnsHeader::new();
        expected_header.id = 16;
        expected_header.opcode = 1;
        expected_header.aa = true;
        expected_header.rd = true;
        expected_header.ra = true;
        expected_header.z = 4;
        expected_header.rcode = DnsResponseCode::NotImplemented;
        expected_header.qd_count = 1;

        let expected_q1 = DnsQuestion {
            qname: vec!(String::from("www"), 
                String::from("example"),
                String::from("com")
            ),
            qtype: DnsRecordType::AAAA(None),
            qclass: 16
        };
        let expected_q2 = DnsQuestion {
            qname: vec!(String::from("www"), 
                String::from("google"),
                String::from("com")
            ),
            qtype: DnsRecordType::TLSA(None),
            qclass: 4
        };

        let expected = DnsQuery {
            header: expected_header,
            questions: vec!(expected_q1, expected_q2)
        };
        let result = parse_query(&query, true).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn parse_query_test_fail() {
        let query: Vec<u8> = vec!(
            0, 52, //Length of message (52 bytes)
            0b0000_0000, //First byte of id
            0b0001_0000, //Second byte of id (16)
            0b0_0001_1_0_1, //qr (0), opcode (1), aa (1), tc (0), rd (1)
            0b1_100_0100, //ra (1), z (4), rcode (4)
            0, 1, //qd_count
            0, 0, //an_count
            0, 0, //ns_count
            0, 0, //ar_count
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0111, 101, 120, 97, 109, 112, 108, 101, //length (7), example
            0b0000_0011, 99, 111, 109, //length (3), com
            //length (0) !!missing!!
            0, 0b1100_1000, //qtype (200)
            0, 0b0001_0000, //qclass (16)
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0110, 103, 111, 111, 103, 108, 101, //length (6), google
            0b0000_0011, 99, 111, 109, //length (3), com
            0b0000_0000, //length (0)
            0, 0b0010_0000, //qtype (32)
            0, 0b0000_0100 //qclass (4)
        );

        assert_eq!(parse_query(&query, true), None);
    }
}