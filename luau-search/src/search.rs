use mem_analysis::data_interface::DataInterface;
use serde::Serialize;
use std::error::Error as StdErr;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::{Arc, RwLock};

pub trait Search {
    fn search_buffer_next(
        &mut self,
        buffer: &[u8],
        pos: u64,
    ) -> Result<Option<SearchResult>, Box<dyn StdErr>>;
    fn search_buffer(&mut self, buffer: &[u8]) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>>;
    fn search_buffer_with_bases(
        &mut self,
        buffer: &[u8],
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>>;

    fn search_interface(
        &mut self,
        di: Arc<RwLock<Box<DataInterface>>>,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>>;
    fn search_interface_with_bases(
        &mut self,
        di: Arc<RwLock<Box<DataInterface>>>,
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>>;
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
    pub data: Option<Vec<u8>>,
    pub start_pattern: String,
    pub end_pattern: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub section_name: String,
    pub digest: String,
    pub comment: String,
    // pub value: Option<Vec<u8>>
}

impl SearchResult {
    pub fn default() -> Self {
        SearchResult {
            boundary_offset: 0 as u64,
            size: 0 as u64,
            start_pattern: "".to_string(),
            end_pattern: "".to_string(),
            vaddr: 0 as u64,
            paddr: 0 as u64,
            section_name: "".to_string(),
            digest: "".to_string(),
            comment: "".to_string(),
            data: None,
        }
    }

    pub fn new(boundary: u64, sz: u64, spattern: String, epattern: String) -> Self {
        SearchResult {
            boundary_offset: boundary,
            size: sz,
            start_pattern: spattern,
            end_pattern: epattern,
            vaddr: 0 as u64,
            paddr: 0 as u64,
            section_name: "".to_string(),
            digest: "".to_string(),
            comment: "".to_string(),
            data: None,
        }
    }
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
