#![allow(non_snake_case)]

use std::error::Error;
use std::fmt::{ Display, Result, Formatter };
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct GoogleDnsResponse {
    pub Status: u8,
    TC: bool,
    RD: bool,
    RA: bool,
    AD: bool,
    CD: bool,
    Question: Vec<GoogleDnsQuestion>,
    pub Answer: Option<Vec<GoogleDnsAnswer>>,
    pub Authority: Option<Vec<GoogleDnsAnswer>>,
    Comment: Option<String>
}

#[derive(Debug, Deserialize, Clone)]
pub struct GoogleDnsQuestion {
    name: String,
    r#type: u8
}

#[derive(Debug, Deserialize, Clone)]
pub struct GoogleDnsAnswer {
    pub name: String,
    pub r#type: u8,
    pub TTL: u32,
    pub data: String
}

#[derive(Debug)]
pub enum ErrorType {
    ErrMsg(String),
    NxDomain,
}

impl ErrorType {
    pub fn new(msg: &str) -> Self {
        Self::ErrMsg(String::from(msg))
    }
}

impl Display for ErrorType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result {
        match self {
            Self::NxDomain => write!(formatter, "NXDOMAIN"),
            Self::ErrMsg(val) => write!(formatter, "Error: {}", val)
        }
    }
}

impl Error for ErrorType {}