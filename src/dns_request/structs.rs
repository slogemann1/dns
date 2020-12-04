use std::clone::Clone;
use std::net::{ Ipv4Addr, Ipv6Addr };
use serde::{ Deserialize, Serialize };

/// # Struct representing a dns query
#[derive(PartialEq, Debug)]
pub struct DnsQuery {
    ///The header of the query
    pub header: DnsHeader,
    ///The questions the sender wants answered
    pub questions: Vec<DnsQuestion>
}

/// # Struct representing a dns response
#[derive(Debug)]
pub struct DnsResponse {
    ///The header of the response
    pub header: DnsHeader,
    ///The questions the sender asked
    pub questions: Vec<DnsQuestion>,
    ///The answers to the asked questions
    pub answers: Vec<DnsAnswer>,
    ///Authority records for non-recursive queries
    pub authority_records: Vec<DnsAnswer>,
    ///Additional records
    pub additional_records: Vec<DnsAnswer>
}

/// # Struct representing the header of a dns message
#[derive(PartialEq, Debug)]
pub struct DnsHeader {
    ///Identifier for the request
    pub id: u16,
    ///Query/Response bitflag (1: query, 0: response)
    pub qr: bool,
    ///4-bit opcode
    pub opcode: u8,
    ///Authoritative Answer bitflag
    pub aa: bool,
    ///TrunCation bitflag
    pub tc: bool,
    ///Recursion Desired bitflag
    pub rd: bool,
    ///Recursion Avalible bitflag
    pub ra: bool,
    ///3 Reserved bits which should always be 0
    pub z: u8,
    ///Response Code
    pub rcode: DnsResponseCode,
    ///Question Count
    pub qd_count: u16,
    ///Answer Count
    pub an_count: u16,
    ///Name Server resource records count
    pub ns_count: u16,
    ///Additional Resource records count
    pub ar_count: u16
}

/// # Struct representing a question in a dns query or response
#[derive(PartialEq, Clone, Debug)]
pub struct DnsQuestion {
    ///List of domains to be determined
    pub qname: Vec<String>,
    ///Query Type
    pub qtype: DnsRecordType,
    ///Query Class
    pub qclass: u16
}

/// # Struct representing an answer in a dns response
#[derive(Clone, Debug)]
pub struct DnsAnswer {
    ///The list of domains asked for by the question
    pub name: Vec<String>,
    ///Type record type of this answer
    pub r#type: DnsRecordType,
    ///Class of the this answer
    pub class: u16,
    ///Time to Live (number of seconds results can be cached)
    pub ttl: u32,
    ///Length in bytes of the rdata field
    pub rd_length: u16,
    ///Record data of the response
    pub rdata: Vec<u8>
}

/// # Struct representing an authority record of a name server
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct DnsAuthRecord {
    ///Domain name of the primary name server for a zone
    pub mname: Vec<String>,
    ///E-mail domain name to contact those responsible for the name server
    pub rname: Vec<String>,
    ///Version number of the zone
    pub serial: u32,
    ///The time in seconds before the zone should be refreshed
    pub refresh: u32,
    ///The time in seconds before a failed attempt at a refresh should be retried
    pub retry: u32,
    ///The time in seconds until the zone is not guaranteed to be authoritative
    pub expire: u32,
    ///The minimum time to live any resource record from this server should have
    pub minimum: u32
}

/// # A enum which represents the possible response codes for a dns message
#[derive(PartialEq, Debug)]
pub enum DnsResponseCode {
    ///The default response code
    NoError,
    ///The response code for incorrectly formatted messages
    FormatError,
    ///The response code for an internal server issue which leads to the record not being accessible
    ServerFailure,
    ///The response code indicating a record for a domain cannot be found
    NxDomain,
    ///The response code for queries which cannot be handled by the server due to lack of implementation
    NotImplemented,
    ///The response code for queries the server does not wish to respond to
    Refused
}

/// # An enum which represents the most common possible record types that are queried and returned
///Record types that come without associated data (i.e. those from parsed questions) will by default have the 
///value of None 
#[derive(PartialEq, Debug, Clone)]
pub enum DnsRecordType {
    ///An A record (ipv4 address) and its associated rdata field
    A(Option<Vec<u8>>), //1
    ///An AAAA record (ipv6 address) and its associated rdata field
    AAAA(Option<Vec<u8>>), //28
    ///A CNAME record (canonical name: the domain name an alias refers to) and its associated rdata field
    CNAME(Option<Vec<u8>>), //5
    ///A MX record (mail exchange) and its associated rdata field
    MX(Option<Vec<u8>>), //15
    ///A LOC record (location) and its associated rdata field
    LOC(Option<Vec<u8>>), //29
    ///A RP record (responsible person) and its associated rdata field
    RP(Option<Vec<u8>>), //17
    ///A TLSA record (TLS certificate record) and its associated rdata field
    TLSA(Option<Vec<u8>>), //52
    ///A PTR record (pointer to a cname record) and its associated rdata field
    PTR(Option<Vec<u8>>), //12
    ///A TXT record and its associated rdata field
    TXT(Option<Vec<u8>>), //16
    ///A SOA record (authority record: provides information about the name server of a domain)
    ///with a [DnsAuthRecord](DnsAuthRecord) struct
    SOA(Option<DnsAuthRecord>), //6
    ///A stand-in for unimplemented record types with its associated record code
    NotImplemented(u8)
}

impl DnsResponse {
    ///Returns the default configuration of a DnsResponse to be added upon.
    ///The header fields id, aa, tc, rd, ra, and rcode will likely need to be set later
    pub fn default() -> Self {
        let header = DnsHeader {
            id: 0, //Id should be set later
            qr: true, //Response
            opcode: 0, //Standard Query Response
            aa: false, //All results are from cache
            tc: false, //Not truncated
            rd: true, //Most queries desire recursion 
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

    ///Sets the id of the header field of the Response
    pub fn id(mut self, id: u16) -> Self {
        self.header.id = id;
        self
    }

    ///Sets the rd bitflag of the header field of the Response
    pub fn rd(mut self, rd: bool) -> Self {
        self.header.rd = rd;
        self
    }

    ///Sets the opcode of the header field of the Response
    pub fn opcode(mut self, opcode: u8) -> Self {
        self.header.opcode = opcode;
        self
    }

    ///Sets the response code of the header field of the Response
    pub fn rcode(mut self, rcode: DnsResponseCode) -> Self {
        self.header.rcode = rcode;
        self
    }

    ///Sets the additions resource records count of the header field of the Response (will later be removed)
    pub fn ar_count(mut self, ar_count: u16) -> Self {
        self.header.ar_count = ar_count;
        self
    }

    ///Adds an answer to the response
    pub fn add_answer(mut self, answer: DnsAnswer) -> Self {
        self.answers.push(answer);
        self.header.an_count += 1;
        self
    }

    ///Adds a question to the response
    pub fn add_question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self.header.qd_count += 1;
        self
    }

    ///Adds an authority record to the response
    pub fn add_auth_record(mut self, auth_record: DnsAnswer) -> Self {
        self.authority_records.push(auth_record);
        self.header.ns_count += 1;
        self
    }

    ///Converts the response to the binary format so it can be sent over a connection.
    ///The tcp parameter indicates whether the request will be sent over tcp or udp
    ///to account for the length bytes in a tcp response
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
    fn build(&self) -> Vec<u8> {
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

    pub(super) fn new() -> Self {
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
    ///Returns the default configuration of a DnsAnswer to be added upon.
    ///The fields name, type, and ttl will likely need to be set later
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

    ///Sets the name of the answer as a list of domains
    pub fn name(mut self, name: Vec<String>) -> Self {
        self.name = name;
        self
    }

    ///Sets the class of the answer
    pub fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }

    ///Sets the time to live of the answer
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    ///Adds a resource record to the answer
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

    fn build(&self) -> Vec<u8> {
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
    fn build(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.append(&mut domain_list_to_bytes(&self.qname));
        result.append(&mut (self.qtype.to_byte().0 as u16).to_be_bytes().to_vec());
        result.append(&mut self.qclass.to_be_bytes().to_vec());

        result
    }
}

impl DnsAuthRecord {
    ///Returns a new instance of a DnsAuthRecord to be added upon.
    ///The fields will need to be set later
    pub fn new() -> Self {
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

    ///Sets the mname field of the authority record as a list of domains
    pub fn mname(mut self, mname: Vec<String>) -> Self {
        self.mname = mname;
        self
    }

    ///Sets the rname field of the authority record as a list of domains
    pub fn rname(mut self, rname: Vec<String>) -> Self {
        self.rname = rname;
        self
    }

    ///Sets the serial field of the authority record
    pub fn serial(mut self, serial: u32) -> Self {
        self.serial = serial;
        self
    }

    ///Sets the refresh field of the authority record
    pub fn refresh(mut self, refresh: u32) -> Self {
        self.refresh = refresh;
        self
    }

    ///Sets the retry field of the authority record
    pub fn retry(mut self, retry: u32) -> Self {
        self.retry = retry;
        self
    }

    ///Sets the expire field of the authority record
    pub fn expire(mut self, expire: u32) -> Self {
        self.expire = expire;
        self
    }

    ///Sets the minimum field of the authority record
    pub fn minimum(mut self, minimum: u32) -> Self {
        self.minimum = minimum;
        self
    }

    fn build(&self) -> Vec<u8> {
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
            Self::NxDomain => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5
        }
    }

    pub(super) fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NxDomain,
            4 => Self::NotImplemented,
            _ => Self::Refused,
        }
    }
}

///All new functions will return None upon failure.
///Those that cannot fail have the Option type to maintain consistency
impl DnsRecordType {
    pub(super) fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::A(None),
            28 => Self::AAAA(None),
            5 => Self::CNAME(None),
            15 => Self::MX(None),
            29 => Self::LOC(None),
            17 => Self::RP(None),
            52 => Self::TLSA(None),
            12 => Self::PTR(None),
            16 => Self::TXT(None),
            6 => Self::SOA(None),
            num => Self::NotImplemented(num)
        }
    }

    pub(crate) fn to_byte(&self) -> (u8, Option<Vec<u8>>) {
        match self.clone() {
            Self::A(val) => (1, val),
            Self::AAAA(val) => (28, val),
            Self::CNAME(val) => (5, val),
            Self::MX(val) => (15, val),
            Self::LOC(val) => (29, val),
            Self::RP(val) => (17, val),
            Self::TLSA(val) => (52, val),
            Self::PTR(val) => (12, val),
            Self::TXT(val) => (16, val),
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

    ///Creates a new A record from a string containing an ipv4 address
    pub fn new_a(ipv4: &str) -> Option<Self> {
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

    ///Creates a new AAAA record from a string containing an ipv6 address
    pub fn new_aaaa(ipv6: &str) -> Option<Self> {
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

    ///Creates a new SOA record from a [DnsAuthRecord](DnsAuthRecord)
    pub fn new_soa(auth_record: DnsAuthRecord) -> Option<Self> {
        Some(Self::SOA(Some(auth_record)))
    }

    ///Creates a new TXT record from a string
    pub fn new_txt(text: &str) -> Option<Self> {
        Some(
            Self::TXT(
                Some(
                    text.as_bytes().to_vec()
                )
            )
        )
    }

    ///Creates a new CNAME record (unimplemented)
    pub fn new_cname(cname: &str) -> Option<Self> {
        None
    }

    ///Creates a new MX record (unimplemented)
    pub fn new_mx(_val: &str) -> Option<Self> {
        None
    }

    ///Creates a new LOC record (unimplemented)
    pub fn new_loc(_val: &str) -> Option<Self> {
        None
    }

    ///Creates a new RP record (unimplemented)
    pub fn new_rp(_val: &str) -> Option<Self> {
        None
    }

    ///Creates a new TLSA record (unimplemented)
    pub fn new_tlsa(_val: &str) -> Option<Self> {
        None
    }

    ///Creates a new PTR record (unimplemented)
    pub fn new_ptr(_val: &str) -> Option<Self> {
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
        .record(DnsRecordType::new_a("192.168.0.1"));

        let resp = DnsResponse::default()
        .id(32)
        .opcode(3)
        .rcode(DnsResponseCode::Refused)
        .add_answer(ans1);

        let expected: Vec<u8> = vec!(
            //Header:
            0, 43, //Length of message (43 bytes)
            0b0000_0000, //First byte of id
            0b0010_0000, //Second byte of id (32)
            0b1_0011_0_0_1, //qr (1), opcode (3), aa (0), tc (0), rd (1)
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