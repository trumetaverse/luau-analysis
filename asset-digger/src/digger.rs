use std::error::{Error as StdErr};


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
}

#[derive(Debug, PartialEq, Clone)]
pub struct SearchResult {
    pub vaddr : u64,
    pub paddr: u64,
    pub data : Vec<u8>,
    pub start_pattern: String,
    pub end_pattern : String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RegexSearch {
    pub start_pattern: String,
    pub end_pattern : String,
    pub location: u64,
    pub offset: OffsetType,
}

impl Search for RegexSearch {
    fn search(&self) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        return Ok(None);
    }
}