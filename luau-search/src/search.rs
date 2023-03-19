use std::error::Error as StdErr;
use serde::{Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};

pub trait Search {
    fn search_buffer_next(&mut self, buffer: &[u8], pos : u64) -> Result<Option<SearchResult>, Box<dyn StdErr>>;
    fn search_buffer(&mut self, buffer: &[u8]) -> Result<Vec<SearchResult>, Box<dyn StdErr>>;
    fn search_buffer_with_bases(&mut self, buffer: &[u8], phys_base: u64, virt_base : u64) -> Result<Vec<SearchResult>, Box<dyn StdErr>>;
}

#[derive(Debug, PartialEq, Clone)]
pub enum OffsetType {
    RelativeOffset,
    VirtualAddress,
    PhysicalAddress,
    None,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct SearchResult {
    pub boundary_offset: u64,
    pub size: u64,
    // pub data: Vec<u8>,
    pub start_pattern: String,
    pub end_pattern: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub section_name: String,
    pub digest: String,
}


impl Display for SearchResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "start_pattern: {} end_pattern: {} start={:08x} base (paddr={:08x} vaddr={:08x}) size={:08x}",
            self.start_pattern, self.end_pattern, self.boundary_offset, self.size, self.paddr, self.vaddr
        )
    }
}