use std::sync::{ Mutex, MutexGuard };
use std::time::Duration;
use std::thread;
use rusqlite::{ Connection, NO_PARAMS };
use lazy_static;

use crate::dns_request::{ DnsRecordType, DnsAnswer, DnsAuthRecord };
use crate::google_dns;

//TODO: get/set ptr record, add functionality for commented out record types
//TODO: add update and check for val exists

lazy_static! {
    static ref CONNECTION: Mutex<Connection> = {
        let conn = Connection::open("./data/domains.db").expect("Failed to create connection to database");
        Mutex::new(conn)
    };
}

pub fn init_db() {
    lazy_static::initialize(&CONNECTION);
}

fn get_db_access() -> MutexGuard<'static, Connection> {
    match CONNECTION.lock() {
        Ok(val) => val,
        Err(_) => {
            thread::sleep(Duration::from_millis(1000));
            get_db_access()
        }
    }
}

pub fn get_record(name: &Vec<String>, record_type: DnsRecordType) -> Option<DnsAnswer> {
    let column = match record_type {
        DnsRecordType::A(_) => "ipv4",
        DnsRecordType::AAAA(_) => "ipv6",
        DnsRecordType::CNAME(_) => "cname",
        DnsRecordType::MX(_) => "mx",
        DnsRecordType::LOC(_) => "loc",
        DnsRecordType::RP(_) => "rp",
        DnsRecordType::TLSA(_) => "certificate",
        DnsRecordType::SOA(_) => "authority",
        //DnsRecordType::PTR(_) => return get_ptr_record(name),
        _ => return None
    };
    if name.len() == 0 {
        return None;
    }

    let domain = name[name.len()-1].clone();
    let name_short = name[0..name.len()].join(".");
    let request = format!(
        "SELECT {}, ttl FROM {} WHERE name = '{}'",
        column, domain, name_short
    );

    let db = get_db_access();
    let (value, ttl): (String, String) = match db.query_row(&request, NO_PARAMS, |row| { Ok((row.get(0), row.get(1))) }) {
        Ok((Ok(value), Ok(ttl))) => (value, ttl),
        _ => {
            drop(db);
            return save_record(name, record_type);
        }
    };
    drop(db);
    if value == "" {
        return save_record(name, record_type);
    }

    let ans = DnsAnswer::default()
    .ttl(ttl.parse::<u32>().unwrap());

    Some(get_ans_from_val(&value, record_type, ans))
}

fn save_record(name: &Vec<String>, record_type: DnsRecordType) -> Option<DnsAnswer> {
    let column = match record_type {
        DnsRecordType::A(_) => "ipv4",
        DnsRecordType::AAAA(_) => "ipv6",
        DnsRecordType::CNAME(_) => "cname",
        DnsRecordType::MX(_) => "mx",
        DnsRecordType::LOC(_) => "loc",
        DnsRecordType::RP(_) => "rp",
        DnsRecordType::TLSA(_) => "certificate",
        DnsRecordType::SOA(_) => "authority",
        //DnsRecordType::PTR(_) => return save_ptr_record(name),
        _ => return None
    };

    let google_answer = match google_dns::request_query(name, record_type) {
        Ok(val) => val,
        Err(_) => return None
    };
    let value = get_val_from_ans(&google_answer);

    let domain = name[name.len()-1].clone();
    let name_short = name[0..name.len()].join(".");

    let request = format!("SELECT name FROM sqlite_master WHERE tbl_name = '{}'", domain);
    let db = get_db_access();
    let results = db.query_row(&request, NO_PARAMS, |_| Ok(()));
    if let Err(err) = results {
        let request = format!(
            "CREATE TABLE {}(
                name TEXT PRIMARY KEY,
                ipv4 TEXT,
                ipv6 TEXT,
                cname TEXT,
                mx TEXT,
                loc TEXT,
                rp TEXT,
                certificate TEXT,
                authority TEXT,
                ttl INT
            );",
            domain
        );
        match db.execute(&request, NO_PARAMS) {
            Ok(val) => (),
            Err(err) => println!("{}", err)
        };
    }

    let request = format!("SELECT name FROM {} WHERE name = '{}'", domain, name_short);
    let results = db.query_row(&request, NO_PARAMS, |_| Ok(()));
    if let Err(err) = results {
        let request = format!(
            "INSERT INTO {} VALUES (
                '{}',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                {}
            );",
            domain,
            name_short,
            google_answer.ttl
        );
        match db.execute(&request, NO_PARAMS) {
            Ok(_) => (),
            Err(err) => println!("{}", err)
        };
    }

    let request = format!("UPDATE {} SET {} = '{}' WHERE name = '{}'", domain, column, value, name_short);
    match db.execute(&request, NO_PARAMS) {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }

    Some(google_answer)
}

fn get_ans_from_val(value: &str, record_type: DnsRecordType, mut ans: DnsAnswer) -> DnsAnswer {
    let record = match record_type {
        DnsRecordType::A(_) => DnsRecordType::new_a(value),
        DnsRecordType::AAAA(_) => DnsRecordType::new_aaaa(value),
        DnsRecordType::CNAME(_) => DnsRecordType::new_cname(value),
        DnsRecordType::MX(_) => DnsRecordType::new_mx(value),
        DnsRecordType::LOC(_) => DnsRecordType::new_loc(value),
        DnsRecordType::RP(_) => DnsRecordType::new_rp(value),
        DnsRecordType::TLSA(_) => DnsRecordType::new_tlsa(value),
        DnsRecordType::SOA(_) => {
            DnsRecordType::new_soa(parse_auth_record(value))
        },
        DnsRecordType::PTR(_) => DnsRecordType::new_ptr(value),
        _ => return ans
    };

    ans.record(record)
}

fn get_val_from_ans(ans: &DnsAnswer) -> String {
    match ans.r#type.clone() {
        DnsRecordType::A(_) => {
            let mut octets: Vec<String> = Vec::new();
            for byte in &ans.rdata {
                octets.push(format!("{}", *byte));
            }
            octets.join(".")
        },
        DnsRecordType::AAAA(_) => {
            let mut octets: Vec<String> = Vec::new();
            for byte in &ans.rdata {
                octets.push(format!("{}", *byte));
            }
            octets.join(":")
        },
        //DnsRecordType::CNAME(_) => ,
        //DnsRecordType::MX(_) => DnsRecordType::new_mx(value),
        //DnsRecordType::LOC(_) => DnsRecordType::new_loc(value),
        //DnsRecordType::RP(_) => DnsRecordType::new_rp(value),
        //DnsRecordType::TLSA(_) => DnsRecordType::new_tlsa(value),
        DnsRecordType::SOA(val) => {
            stringify_auth_record(&val.unwrap())
        },
        //DnsRecordType::PTR(_) => DnsRecordType::new_ptr(&value),
        _ => String::from("")
    }
}

fn parse_auth_record(json: &str) -> DnsAuthRecord {
    match serde_json::from_str(json) {
        Ok(val) => val,
        Err(_) => DnsAuthRecord::new()
    }
}

fn stringify_auth_record(auth_rec: &DnsAuthRecord) -> String {
    match serde_json::to_string(auth_rec) {
        Ok(val) => val,
        Err(_) => String::new()
    }
}