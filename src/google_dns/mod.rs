use std::error::Error;

mod structs;

use crate::dns_request::{ DnsRecordType, DnsAuthRecord, DnsAnswer };
pub use structs::*;

pub fn request_query(name: &Vec<String>, r#type: DnsRecordType) -> Result<DnsAnswer, Box<dyn Error>> {
    let (u8_type, _) = DnsRecordType::to_byte(&r#type);
    let name = domains_to_str(name);
    
    let response = reqwest::blocking::get(&format!("https://8.8.8.8/resolve?name={}&type={}", name, u8_type))?
    .json::<GoogleDnsResponse>()?;

    if response.Status == 3 {
        return Err(Box::new(ErrorType::NxDomain));
    }

    match r#type {
        DnsRecordType::SOA(_) => Ok(to_soa(response)?),
        DnsRecordType::A(_) => Ok(to_a(response)?),
        DnsRecordType::AAAA(_) => Ok(to_aaaa(response)?),
        _ => Err(Box::new(ErrorType::new("Requested type not implemented")))
    }
}

fn to_a(response: GoogleDnsResponse) -> Result<DnsAnswer, Box<dyn Error>> {
    if let None = response.Answer {
        return Err(Box::new(ErrorType::new("No answers")));
    }

    let answer_results = response.Answer.unwrap();
    let answer = get_ans_from_rec_type(&answer_results, 1); //1 = A record
    if let None = answer {
        let cname_answer = get_ans_from_rec_type(&answer_results, 5); //5 = CNAME record
        if let Some(ans) = cname_answer {
            return request_query(&str_to_domains(&ans.data), DnsRecordType::A(None));
        }
        else {
            return Err(Box::new(ErrorType::new("No cname response")));
        }
    }
    let answer = answer.unwrap();

    let record = match DnsRecordType::new_a(&answer.data) {
        Some(val) => val,
        None => return Err(Box::new(ErrorType::new("Invalid ipv4")))
    };

    Ok(answer_from_record(Some(record), answer))
}

fn to_aaaa(response: GoogleDnsResponse) -> Result<DnsAnswer, Box<dyn Error>> {
    if let None = response.Answer {
        return Err(Box::new(ErrorType::new("No answers")));
    }

    let answer_results = response.Answer.unwrap();
    let answer = get_ans_from_rec_type(&answer_results, 28); //28 = AAAA record
    if let None = answer {
        let cname_answer = get_ans_from_rec_type(&answer_results, 5); //5 = CNAME record
        if let Some(ans) = cname_answer {
            return request_query(&str_to_domains(&ans.data), DnsRecordType::AAAA(None));
        }
        else {
            return Err(Box::new(ErrorType::new("No cname response")));
        }
    }
    let answer = answer.unwrap();

    let record = match DnsRecordType::new_aaaa(&answer.data) {
        Some(val) => val,
        None => return Err(Box::new(ErrorType::new("Invalid ipv6")))
    };

    Ok(answer_from_record(Some(record), answer))
}

fn to_soa(response: GoogleDnsResponse) -> Result<DnsAnswer, Box<dyn Error>> {
    if let None = response.Authority {
        return Err(Box::new(ErrorType::new("No authority response")));
    }

    let auth_results = response.Authority.unwrap();
    if auth_results.len() == 0 {
        return Err(Box::new(ErrorType::new("No authority response")));
    }

    let answers: Vec<&str> = auth_results[0].data.split(" ").collect();
    if answers.len() < 7 {
        return Err(Box::new(ErrorType::new("Invalid rdata field")));
    }

    let mname = str_to_domains(answers[0]);
    let rname = str_to_domains(answers[1]);
    let serial = answers[2].parse::<u32>()?;
    let refresh = answers[3].parse::<u32>()?;
    let retry = answers[4].parse::<u32>()?;
    let expire = answers[5].parse::<u32>()?;
    let minimum = answers[6].parse::<u32>()?;

    let auth_rec = DnsAuthRecord {
        mname: mname,
        rname: rname,
        serial: serial,
        refresh: refresh,
        retry: retry,
        expire: expire,
        minimum: minimum
    };

    let record = DnsRecordType::new_soa(auth_rec);
    Ok(answer_from_record(record, auth_results[0].clone()))
}

fn get_ans_from_rec_type(answers: &Vec<GoogleDnsAnswer>, rec_type: u8) -> Option<GoogleDnsAnswer> {
    for answer in answers {
        if answer.r#type == rec_type {
            return Some(answer.clone());
        }
    }

    None
}

fn answer_from_record(record: Option<DnsRecordType>, answer: GoogleDnsAnswer) -> DnsAnswer {
    DnsAnswer::default()
    .record(record)
    .ttl(answer.TTL)
}

fn str_to_domains(url: &str) -> Vec<String> {
    let domains: Vec<&str> = url.split(".").collect();

    let mut filtered_domains: Vec<String> = Vec::new();
    for domain in domains {
        if domain.trim() != "" {
            filtered_domains.push(String::from(domain));
        }
    }

    filtered_domains
}

fn domains_to_str(domains: &Vec<String>) -> String {
    let mut url = String::new();

    for domain in domains {
        url = format!("{}{}.", url, domain);
    }

    String::from(&url[..url.len()-1])
}