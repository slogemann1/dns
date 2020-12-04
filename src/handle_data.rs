use crate::dns_request::{ DnsResponse, DnsAnswer, DnsRecordType, DnsResponseCode };
use crate::dns_request;
use crate::database;

pub fn handle_message(buffer: Vec<u8>, tcp: bool) -> Option<Vec<u8>> {
    let query = match dns_request::parse_query(&buffer, tcp) {
        Some(val) => val,
        None => {
            return None;
        }
    };

    let mut response = DnsResponse::default()
    .id(query.header.id)
    .rd(query.header.rd);
    if !query.header.rd {
        response = response.rcode(DnsResponseCode::NxDomain);
    }

    for question in query.questions {
        response = response.add_question(question.clone());

        response = match question.qtype {
            DnsRecordType::A(_) => handle_a(question.qname.clone(), query.header.rd, response),
            DnsRecordType::AAAA(_) => handle_aaaa(question.qname.clone(), query.header.rd, response),
            DnsRecordType::TXT(_) => handle_txt(question.qname.clone(), response),
            DnsRecordType::NotImplemented(num) => {
                println!("Record Type not yet defined: {}", num);
                continue;
            },
            val => {
                println!("Query not yet implemented: {:#?}", val);
                continue;
            }
        }
    }

    Some(response.build(tcp))
}

fn handle_a(name: Vec<String>, rd: bool, mut response: DnsResponse) -> DnsResponse {
    let mut answer;
    let name = {
        let name_temp;
        if name[&name.len()-1] == "home" {
            name_temp = name[..name.len()-1].to_vec();
        }
        else {
            name_temp = name;
        }

        name_temp
    };

    if !rd {
        answer = match database::get_record(&name, DnsRecordType::SOA(None)) {
            Some(val) => val,
            None => {
                response = response.rcode(DnsResponseCode::NxDomain);
                return response;
            }
        };
        answer = answer.name(name);

        response = response.add_answer(answer);
    }
    else {
        answer = match database::get_record(&name, DnsRecordType::A(None)) {
            Some(val) => val,
            None => {
                response = response.rcode(DnsResponseCode::NxDomain);
                return response;
            }
        };
        answer = answer.name(name);

        response = response.add_answer(answer);
    }

    response
}

fn handle_aaaa(name: Vec<String>, rd: bool, mut response: DnsResponse) -> DnsResponse {
    let mut answer;
    let name = {
        let name_temp;
        if name[&name.len()-1] == "home" {
            name_temp = name[..name.len()-1].to_vec();
        }
        else {
            name_temp = name;
        }

        name_temp
    };

    if !rd {
        answer = match database::get_record(&name, DnsRecordType::SOA(None)) {
            Some(val) => val,
            None => {
                response = response.rcode(DnsResponseCode::NxDomain);
                return response;
            }
        };
        answer = answer.name(name);

        response = response.add_answer(answer);
    }
    else {
        answer = match database::get_record(&name, DnsRecordType::AAAA(None)) {
            Some(val) => val,
            None => {
                response = response.rcode(DnsResponseCode::NxDomain);
                return response;
            }
        };
        answer = answer.name(name);

        response = response.add_answer(answer);
    }

    response
}

fn handle_txt(fields: Vec<String>, mut response: DnsResponse) -> DnsResponse {
    for field in fields {
        let mut answer = DnsAnswer::default()
        .name(vec!(field.clone()))
        .ttl(30);

        let record = DnsRecordType::new_txt(
            match field.as_str() {
                "version" => "\"version=1.0\"",
                "bind" => "\"bind=hello\"",
                _ => "unknown=unknown"
            }
        );

        answer = answer.record(record);

        response = response.add_answer(answer);
    }

    response
}