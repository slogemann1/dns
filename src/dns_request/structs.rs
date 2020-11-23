use std::clone::Clone;
use std::net::{ Ipv4Addr, Ipv6Addr };

#[derive(PartialEq, Debug)]
pub struct DnsQuery {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>
}

#[derive(Debug)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub authority_records: Vec<DnsAnswer>,
    pub additional_records: Vec<DnsAnswer>
}

#[derive(PartialEq, Debug)]
pub struct DnsHeader {
    pub id: u16, //Identifier for the Request
    pub qr: bool, //Query (0) / Response (1)
    pub opcode: u8, //4 bit opcode
    pub aa: bool, //Authoritative Answer
    pub tc: bool, //TrunCation
    pub rd: bool, //Recursion Desired
    pub ra: bool, //Recursion Avalible
    pub z: u8, //3 Reserved Bits
    pub rcode: DnsResponseCode, //Response Code
    pub qd_count: u16, //Question Count
    pub an_count: u16, //Answer Count
    pub ns_count: u16, //Name Server Resource Records Count
    pub ar_count: u16 //Additional Resource Records Count
}

#[derive(PartialEq, Clone, Debug)]
pub struct DnsQuestion {
    pub qname: Vec<String>, //List of domains to be determined
    pub qtype: DnsRecordType, //Query Type
    pub qclass: u16 //Query Class
}

#[derive(Clone, Debug)]
pub struct DnsAnswer {
    pub name: Vec<String>, //Like DnsRequest.qname
    pub r#type: DnsRecordType, //Type of rdata
    pub class: u16, //Class of rdata
    pub ttl: u32, //Number of seconds results can be cached
    pub rd_length: u16, //Length of rdata
    pub rdata: Vec<u8> //Data of response (currently ip format)
}

#[derive(PartialEq, Debug, Clone)]
pub struct DnsAuthRecord {
    pub mname: Vec<String>,
    pub rname: Vec<String>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32
}

#[derive(PartialEq, Debug)]
pub enum DnsResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused
}

#[derive(PartialEq, Debug, Clone)]
pub enum DnsRecordType {
    A(Option<Vec<u8>>), //1
    AAAA(Option<Vec<u8>>), //28
    CNAME(Option<Vec<u8>>), //5
    MX(Option<Vec<u8>>), //15
    LOC(Option<Vec<u8>>), //29
    RP(Option<Vec<u8>>), //17
    TLSA(Option<Vec<u8>>), //52
    PTR(Option<Vec<u8>>), //12
    SOA(Option<DnsAuthRecord>), //6
    NotImplemented(u8),
}

impl DnsResponse {
    pub fn default() -> Self {
        let header = DnsHeader {
            id: 0, //Id should be set later
            qr: true, //Response
            opcode: 0, //Standard Query Response
            aa: false, //All results are from cache
            tc: false, //Not truncated
            rd: false, //Field for requester
            ra: true, //This server should simulate recursion
            z: 0, //Must be 0
            rcode: DnsResponseCode::NoError,
            qd_count: 0, //Field for requester
            an_count: 0, //0 Answers by default
            ns_count: 0, //Assuming no other records
            ar_count: 0 //Assuming no other records
        };

        DnsResponse {
            header: header,
            questions: Vec::new(),
            answers: Vec::new(),
            authority_records: Vec::new(),
            additional_records: Vec::new()
        }
    }

    pub fn id(mut self, id: u16) -> Self {
        self.header.id = id;
        self
    }

    pub fn rd(mut self, rd: bool) -> Self {
        self.header.rd = rd;
        self
    }

    pub fn opcode(mut self, opcode: u8) -> Self {
        self.header.opcode = opcode;
        self
    }

    pub fn rcode(mut self, rcode: DnsResponseCode) -> Self {
        self.header.rcode = rcode;
        self
    }

    pub fn ns_count(mut self, ns_count: u16) -> Self {
        self.header.ns_count = ns_count;
        self
    }

    pub fn ar_count(mut self, ar_count: u16) -> Self {
        self.header.ar_count = ar_count;
        self
    }

    pub fn add_answer(mut self, answer: DnsAnswer) -> Self {
        self.answers.push(answer);
        self.header.an_count += 1;
        self
    }

    pub fn add_question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self.header.qd_count += 1;
        self
    }

    pub fn add_auth_record(mut self, auth_record: DnsAnswer) -> Self {
        self.authority_records.push(auth_record);
        self.header.ns_count += 1;
        self
    }

    pub fn build(&self, tcp: bool) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut self.header.build().clone());

        for question in &self.questions {
            result.append(&mut question.build().clone());
        }
        for answer in &self.answers {
            result.append(&mut answer.build().clone());
        }
        for auth_record in &self.authority_records {
            result.append(&mut auth_record.build().clone());
        }
        for add_record in &self.additional_records {
            result.append(&mut add_record.build().clone());
        }

        if !tcp {
            return result;
        }

        let mut len_result = (result.len() as u16).to_be_bytes().to_vec();
        len_result.append(&mut result);

        len_result
    }
}

impl DnsHeader {
    pub fn build(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut self.id.to_be_bytes().to_vec()); //Add id first

        //First Flag Byte: qr opcode*3 aa tc rd
        let mut flag_byte_1: u8 = self.rd as u8;
        flag_byte_1 |= (self.tc as u8) << 1;
        flag_byte_1 |= (self.aa as u8) << 2;
        flag_byte_1 |= (self.opcode) << 3;
        flag_byte_1 |= (self.qr as u8) << 7;
        result.push(flag_byte_1);

        //Second Flag Byte: ra z*3 rcode*4
        let mut flag_byte_2: u8 = self.rcode.to_byte();
        flag_byte_2 |= self.z << 4;
        flag_byte_2 |= (self.ra as u8) << 7;
        result.push(flag_byte_2);

        result.append(&mut self.qd_count.to_be_bytes().to_vec()); //Add question count
        result.append(&mut self.an_count.to_be_bytes().to_vec()); //Add answer count
        result.append(&mut self.ns_count.to_be_bytes().to_vec()); //Add ns records count
        result.append(&mut self.ar_count.to_be_bytes().to_vec()); //Add additional records count

        result
    }

    pub fn new() -> Self {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: DnsResponseCode::NoError,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0
        }
    }
}

impl DnsAnswer {
    pub fn default() -> Self {
        Self {
            name: Vec::new(),
            r#type: DnsRecordType::A(None), //A record type
            class: 1, //IP address
            ttl: 0, //0 secs to live
            rd_length: 0,
            rdata: Vec::new()
        }
    }

    pub fn name(mut self, name: Vec<String>) -> Self {
        self.name = name;
        self
    }

    pub fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }

    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn record(mut self, r_type: Option<DnsRecordType>) -> Self {
        let r_type = match r_type {
            Some(val) => val,
            None => return self
        };
        self.r#type = r_type;

        let (_, rdata) = self.r#type.to_byte();
        if let Some(val) = rdata {
            self.rd_length = val.len() as u16;
            self.rdata = val; 
        }

        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut domain_list_to_bytes(&self.name));
        result.append(&mut (self.r#type.to_byte().0 as u16).to_be_bytes().to_vec());
        result.append(&mut self.class.to_be_bytes().to_vec());
        result.append(&mut self.ttl.to_be_bytes().to_vec());
        result.append(&mut self.rd_length.to_be_bytes().to_vec());
        result.append(&mut self.rdata.clone());

        result
    }
}

impl DnsQuestion {
    pub fn build(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut domain_list_to_bytes(&self.qname));
        result.append(&mut (self.qtype.to_byte().0 as u16).to_be_bytes().to_vec());
        result.append(&mut self.qclass.to_be_bytes().to_vec());

        result
    }
}

impl DnsAuthRecord {
    pub fn default() -> Self {
        DnsAuthRecord {
            mname: Vec::new(),
            rname: Vec::new(),
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0
        }
    }

    pub fn mname(mut self, mname: Vec<String>) -> Self {
        self.mname = mname;
        self
    }

    pub fn rname(mut self, rname: Vec<String>) -> Self {
        self.rname = rname;
        self
    }

    pub fn serial(mut self, serial: u32) -> Self {
        self.serial = serial;
        self
    }

    pub fn refresh(mut self, refresh: u32) -> Self {
        self.refresh = refresh;
        self
    }

    pub fn retry(mut self, retry: u32) -> Self {
        self.retry = retry;
        self
    }

    pub fn expire(mut self, expire: u32) -> Self {
        self.expire = expire;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut domain_list_to_bytes(&self.mname));
        result.append(&mut domain_list_to_bytes(&self.rname));
        result.append(&mut self.serial.to_be_bytes().to_vec());
        result.append(&mut self.refresh.to_be_bytes().to_vec());
        result.append(&mut self.retry.to_be_bytes().to_vec());
        result.append(&mut self.expire.to_be_bytes().to_vec());
        result.append(&mut self.minimum.to_be_bytes().to_vec());

        result
    }
}

impl DnsResponseCode {
    fn to_byte(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5
        }
    }

    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            _ => Self::Refused,
        }
    }
}

impl DnsRecordType {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::A(None),
            28 => Self::AAAA(None),
            5 => Self::CNAME(None),
            15 => Self::MX(None),
            29 => Self::LOC(None),
            17 => Self::RP(None),
            52 => Self::TLSA(None),
            12 => Self::PTR(None),
            6 => Self::SOA(None),
            num => Self::NotImplemented(num)
        }
    }

    fn to_byte(&self) -> (u8, Option<Vec<u8>>) {
        match self.clone() {
            Self::A(val) => (1, val),
            Self::AAAA(val) => (28, val),
            Self::CNAME(val) => (5, val),
            Self::MX(val) => (15, val),
            Self::LOC(val) => (29, val),
            Self::RP(val) => (17, val),
            Self::TLSA(val) => (52, val),
            Self::PTR(val) => (12, val),
            Self::SOA(val) => {
                let mut ret = None;
                if let Some(auth) = val {
                    ret = Some(auth.build());
                }

                (6, ret)
            }
            Self::NotImplemented(val) => (val, Some(Vec::new()))
        }
    }

    pub fn new_A(ipv4: &str) -> Option<Self> {
        let ip: Ipv4Addr = match ipv4.parse() {
            Ok(val) => val,
            Err(_) => return None
        };

        Some(
            Self::A(
                Some(
                    ip.octets().to_vec()
                )
            )
        )
    }

    pub fn new_AAAA(ipv6: &str) -> Option<Self> {
        let ip: Ipv6Addr = match ipv6.parse() {
            Ok(val) => val,
            Err(_) => return None
        };

        Some(
            Self::AAAA(
                Some(
                    ip.octets().to_vec()
                )
            )
        )
    }

    pub fn new_SOA(auth_record: DnsAuthRecord) -> Option<Self> {
        Some(Self::SOA(Some(auth_record)))
    }

    pub fn new_CNAME(cname: &str) -> Option<Self> {
        None
    }

    pub fn new_MX() -> Option<Self> {
        None
    }

    pub fn new_LOC() -> Option<Self> {
        None
    }

    pub fn new_RP() -> Option<Self> {
        None
    }

    pub fn new_TLSA() -> Option<Self> {
        None
    }
}

fn domain_list_to_bytes(list: &Vec<String>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    for domain in list {
        bytes.push(domain.len() as u8);
        bytes.append(&mut domain.as_bytes().to_vec());
    }

    bytes.push(0);

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_list_to_bytes_test() {
        let result = domain_list_to_bytes(&vec!(
            String::from("www"),
            String::from("google"),
            String::from("com")
        ));

        let expected: Vec<u8> = vec!(
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0110, 103, 111, 111, 103, 108, 101, //length (6), google
            0b0000_0011, 99, 111, 109, //length (3), com
            0b0000_0000 //length (0) to indicate end
        );

        assert_eq!(result, expected);
    }

    #[test]
    fn header_test() {
        let mut header = DnsHeader::new();
        header.id = 16;
        header.opcode = 1;
        header.aa = true;
        header.rd = true;
        header.ra = true;
        header.z = 4;
        header.rcode = DnsResponseCode::NotImplemented;

        let expected = vec!(
            0b0000_0000, //First byte of id
            0b0001_0000, //Second byte of id (16)
            0b0_0001_1_0_1, //qr (0), opcode (1), aa (1), tc (0), rd (1)
            0b1_100_0100, //ra (1), z (4), rcode (4)
            0, 0, //qd_count
            0, 0, //an_count
            0, 0, //ns_count
            0, 0 //ar_count
        );

        assert_eq!(header.build(), expected);
    }

    #[test]
    fn response_test() {
        let ans1 = DnsAnswer::default()
        .name(vec!(String::from("www"), String::from("example"), String::from("com")))
        .ttl(200)
        .record(DnsRecordType::new_A("192.168.0.1"));

        let resp = DnsResponse::default()
        .id(32)
        .opcode(3)
        .rcode(DnsResponseCode::Refused)
        .answer(&ans1);

        let expected: Vec<u8> = vec!(
            //Header:
            0, 43, //Length of message (43 bytes)
            0b0000_0000, //First byte of id
            0b0010_0000, //Second byte of id (32)
            0b1_0011_0_0_0, //qr (1), opcode (3), aa (0), tc (0), rd (0)
            0b1_000_0101, //ra (1), z (0), rcode (5)
            0, 0, //qd_count
            0, 1, //an_count (1)
            0, 0, //ns_count
            0, 0, //ar_count
            //Answer:
            0b0000_0011, 119, 119, 119, //length (3), www
            0b0000_0111, 101, 120, 97, 109, 112, 108, 101, //length (7) example
            0b0000_0011, 99, 111, 109, //length (3) com
            0b0000_0000, //length (0) to indicate end
            0, 1, //type (1)
            0, 1, //class (1)
            0, 0, 0, 0b11001000, //ttl (200)
            0, 0b0000_0100, //rd_length (4)
            192, 168, 0, 1 //rdata
        );

        assert_eq!(resp.build(true), expected);
    }
}