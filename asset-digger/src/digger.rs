use std::error::Error as StdErr;

use regex::bytes::Regex;
// use mem_analysis::memory::MemRange;
// use mem_analysis::radare::{RadareMemoryInfo, RadareMemoryInfos};

static ROBLOX_REGEX_START: &str = r"(:?<roblox)";
static ROBLOX_REGEX_END: &str = r"(:?</roblox>)";

pub trait Search {
    fn search(&self) -> Result<Option<SearchResult>, Box<dyn StdErr>>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum OffsetType {
    RelativeOffset,
    VirtualAddress,
    PhysicalAddress,
    None,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SearchResult {
    pub vaddr: u64,
    pub paddr: u64,
    pub data: Vec<u8>,
    pub start_pattern: String,
    pub end_pattern: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RegexSearch {
    pub start_pattern: String,
    pub end_pattern: String,
    pub start: Option<u64>,
    pub stop: Option<u64>,
    pub offset_type: Option<OffsetType>,
}

impl Search for RegexSearch {
    fn search(&self) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        Ok(None)
    }
}

impl RegexSearch {
    pub fn create(
        re_start_tag: &Option<String>,
        re_end_tag: &Option<String>,
        start: Option<u64>,
        stop: Option<u64>,
        offtype: Option<OffsetType>,
    ) -> Result<RegexSearch, Box<dyn StdErr>> {
        let regex_start: Regex = match re_start_tag {
            Some(pattern) => match Regex::new(pattern.as_str()) {
                Ok(r) => r,
                Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
            },
            None => Regex::new(ROBLOX_REGEX_START).unwrap(),
        };

        let regex_end: Regex = match re_end_tag {
            Some(pattern) => match Regex::new(pattern.as_str()) {
                Ok(r) => r,
                Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
            },
            None => Regex::new(ROBLOX_REGEX_END).unwrap(),
        };
        Ok(RegexSearch {
            stop,
            start,
            start_pattern: regex_start.to_string(),
            end_pattern: regex_end.to_string(),
            offset_type: offtype,
        })
    }
}
