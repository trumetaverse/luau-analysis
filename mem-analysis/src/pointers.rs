use multimap::MultiMap;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error as StdErr;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, PartialEq, Clone, Eq, Serialize)]
pub struct PointerIndex {
    pub sources: HashMap<u64, u64>,
    pub sinks: MultiMap<u64, u64>,
}

impl PointerIndex {
    pub fn new() -> Self {
        PointerIndex {
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
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize)]
pub struct PointerRange {
    pub pstart: u64,
    pub pend: u64,

    pub vstart: u64,
    pub vend: u64,

    pub pointer_index: PointerIndex,
}

impl Display for PointerRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "pstart={:08x} vend={:08x}, vstart={:08x} vend={:08x} ",
            self.pstart, self.pend, self.vstart, self.vend
        )
    }
}

impl PointerRange {
    pub fn new(pstart: u64, pend: u64, vstart: u64, vend: u64) -> Self {
        assert_eq!(vstart <= vend, true);
        assert_eq!(pstart <= pend, true);
        PointerRange {
            pstart,
            pend,
            vstart,
            vend,
            pointer_index: PointerIndex::new(),
        }
    }

    pub fn in_vrange(&self, val: u64) -> bool {
        return self.vstart <= val && val < self.vend;
    }

    pub fn in_prange(&self, val: u64) -> bool {
        return self.pstart <= val && val < self.pend;
    }

    pub fn in_range(&self, val: u64) -> bool {
        return self.in_vrange(val) || self.in_prange(val);
    }

    pub fn vsize(&self) -> u64 {
        return self.vend - self.vstart;
    }

    pub fn psize(&self) -> u64 {
        return self.pend - self.pstart;
    }

    pub fn add_vpointer(&mut self, source: u64, sink: u64) -> bool {
        let mut added = false;
        if self.in_vrange(sink) {
            let _dummy = self.pointer_index.add_sink(source, sink);
            added = true;
        }
        if self.in_vrange(source) {
            let _dummy = self.pointer_index.add_source(source, sink);
            added = true;
        }
        return added;
    }
}
