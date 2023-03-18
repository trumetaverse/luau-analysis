use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::error::Error as StdErr;
use rangemap::RangeMap;
use multimap::MultiMap;

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct RangePointer {
    pub start : u64,
    pub end: u64,
    pub sources: HashMap<u64, u64>,
    pub sinks: MultiMap<u64, u64>,
}

impl RangePointer {
    pub fn new(start : u64, end: u64) -> Self {
        RangePointer {
            start,
            end,
            sources: HashMap::new(),
            sinks: MultiMap::new(),
        }
    }
    pub fn add_sink(&mut self, source: u64, sink: u64) -> Result<bool, Box<dyn StdErr>> {
        self.sinks.insert(sink, source);
        return Ok(true);

    }

    pub fn add_source(&mut self, source: u64, sink: u64) -> Result<bool, Box<dyn StdErr>> {
        self.sources.insert(source, sink);
        return Ok(true);
    }

    pub fn in_range(&self, addr : u64) -> bool {
        return self.start <= addr && addr <= self.end
    }
}



#[derive(Debug, PartialEq, Clone)]
pub struct PointerSearch {
    pub src_addrs: RangeMap<u64, Arc<Box<RangePointer>>>,
    pub sink_addrs: RangeMap<u64, Arc<Box<RangePointer>>>,
    // pub valid_ranges: HashMap
    // pub start: Option<u64>,
    // pub stop: Option<u64>,
    // pub offset_type: Option<OffsetType>,
    // pub base_vaddr: Option<u64>,
    // pub base_paddr: Option<u64>,
}

impl PointerSearch {

    pub fn new() -> Self {
        PointerSearch {
            src_addrs: RangeMap::new(),
            sink_addrs: RangeMap::new(),
        }
    }

    pub fn add_range(&mut self, start: u64, end:u64) -> bool {
        let r = Arc::new(Box::new(RangePointer::new(start, end)));
        self.src_addrs.insert(start .. end, r.clone());
        self.sink_addrs.insert(start .. end, r.clone());
        return true;
    }

}