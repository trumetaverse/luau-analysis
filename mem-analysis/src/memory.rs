use crate::buffer::DataBuffer;
use crate::radare::{RadareMemoryInfo, RadareMemoryInfos};
use rangemap::RangeMap;
use serde;
use serde::Deserialize;
use std::fmt::{Display, Formatter, Result as FmtResult};

use log::debug;
use std::io::Write;

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
pub enum BackendType {
    File,
    SliceBuffer,
    FullBuffer,
}

#[derive(Debug, Clone, Eq)]
pub struct MemRange {
    pub vaddr_start: u64,
    pub paddr_start: u64,
    pub vsize: u64,
    pub size: u64,
    pub data: Option<DataBuffer>,
    pub perm: String,
    pub name: String,
    pub backend: Option<BackendType>,
    // source: SourceMeta<'a>,
}

pub trait Memory {
    fn vaddr_in_range(&self, vaddr: u64) -> bool;
    fn paddr_in_range(&self, paddr: u64) -> bool;
    fn get_size(&self) -> u64;
    fn get_vsize(&self) -> u64;
    fn get_vbase_from_vaddr(&self, vaddr: u64) -> Option<u64>;
    fn get_vbase_from_paddr(&self, paddr: u64) -> Option<u64>;
    fn get_vaddr_from_paddr(&self, paddr: u64) -> Option<u64>;
    fn get_paddr_from_vaddr(&self, vaddr: u64) -> Option<u64>;
}

impl PartialEq for MemRange {
    fn eq(&self, other: &Self) -> bool {
        // Equal if all key members are equal
        self.vaddr_start == other.vaddr_start && self.paddr_start == other.paddr_start
    }
}

impl Display for MemRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} perms={} paddr={:08x} size={:08x} vaddr={:08x} vsize={:08x}",
            self.name, self.perm, self.paddr_start, self.size, self.vaddr_start, self.vsize
        )
    }
}

impl MemRange {
    pub fn from_radare_info(radare_info: &RadareMemoryInfo) -> Self {
        MemRange {
            vaddr_start: radare_info.vaddr,
            paddr_start: radare_info.paddr,
            vsize: radare_info.vsize,
            size: radare_info.size,
            data: None,
            perm: radare_info.perm.clone(),
            name: radare_info.name.clone(),
            backend: None,
        }
    }

    pub fn new(
        perm: String,
        name: String,
        vaddr_start: u64,
        paddr_start: u64,
        vsize: u64,
        size: u64,
        data: Option<DataBuffer>,
        backend: Option<BackendType>,
    ) -> Self {
        MemRange {
            vaddr_start,
            paddr_start,
            vsize,
            size,
            data,
            perm,
            name,
            backend,
        }
    }
}

impl Memory for MemRange {
    fn vaddr_in_range(&self, addr: u64) -> bool {
        if self.vaddr_start <= addr && addr <= self.vaddr_start + self.vsize {
            return true;
        }
        false
    }

    fn paddr_in_range(&self, paddr: u64) -> bool {
        if self.paddr_start <= paddr && paddr <= self.paddr_start + self.size {
            return false;
        }
        self.vaddr_in_range(self.get_vaddr_from_paddr(paddr).unwrap())
    }

    fn get_size(&self) -> u64 {
        self.size
    }

    fn get_vsize(&self) -> u64 {
        self.vsize
    }

    fn get_vbase_from_vaddr(&self, vaddr: u64) -> Option<u64> {
        if !self.vaddr_in_range(vaddr) {
            return None;
        }
        Some(self.vaddr_start)
    }

    fn get_vbase_from_paddr(&self, paddr: u64) -> Option<u64> {
        if !self.paddr_in_range(paddr) {
            return None;
        }
        Some(self.vaddr_start)
    }

    fn get_vaddr_from_paddr(&self, paddr: u64) -> Option<u64> {
        if !self.paddr_in_range(paddr) {
            return None;
        }
        let addr = (paddr - self.paddr_start) + self.vaddr_start;
        Some(addr)
    }

    fn get_paddr_from_vaddr(&self, vaddr: u64) -> Option<u64> {
        if !self.vaddr_in_range(vaddr) {
            return None;
        }
        let addr = (vaddr - self.vaddr_start) + self.paddr_start;
        Some(addr)
    }

    // fn set_data(&self) -> () {}
}

#[derive(Debug, Clone)]
pub struct MemRanges {
    vmem_ranges: RangeMap<u64, MemRange>,
    pmem_ranges: RangeMap<u64, MemRange>,
    // pub vmem_ranges: RangeMap<u64, &'a MemRange<'a>>,
    // pub pmem_ranges: RangeMap<u64, &'a MemRange<'a>>,
}

// impl<'de: 'a> Deserialize<'de> for MemoryRanges<'a> {
//     /* ... */
// }

impl MemRanges {
    pub fn new() -> Self {
        // MemoryRanges{vmem_ranges: RangeMap::new(), pmem_ranges: RangeMap::new()}
        MemRanges {
            vmem_ranges: RangeMap::new(),
            pmem_ranges: RangeMap::new(),
        }
    }

    pub fn add_mem_range(&mut self, mr: MemRange) {
        // self.vmem_ranges.insert(mr.vaddr_start..mr.vaddr_start+mr.vsize, mr);
        // self.pmem_ranges.insert(mr.paddr_start..mr.paddr_start+mr.size, mr);
        // debug!("adding {} to the memranges.", mr);
        let vsz: u64 = if mr.vsize == 0 { 1 } else { mr.vsize };
        let sz: u64 = if mr.size == 0 { 1 } else { mr.size };
        self.vmem_ranges
            .insert(mr.vaddr_start..mr.vaddr_start + vsz, mr.clone());
        self.pmem_ranges
            .insert(mr.paddr_start..mr.paddr_start + sz, mr);
    }

    pub fn get_paddr_range(&self, paddr: u64) -> Option<MemRange> {
        return self.pmem_ranges.get(&paddr).cloned();
    }

    pub fn get_vaddr_range(&self, vaddr: u64) -> Option<MemRange> {
        return self.vmem_ranges.get(&vaddr).cloned();
    }
    pub fn has_paddr(&self, paddr: u64) -> bool {
        self.pmem_ranges.contains_key(&paddr)
    }

    pub fn has_vaddr(&self, vaddr: u64) -> bool {
        self.vmem_ranges.contains_key(&vaddr)
    }

    pub fn from_radare_infos(radare: &RadareMemoryInfos) -> MemRanges {
        let mut mrs = MemRanges::new();
        debug!("Loading {} memory ranges and sections.", radare.items.len());
        for info in radare.items.iter() {
            let mr = MemRange::from_radare_info(info);
            mrs.add_mem_range(mr);
        }
        mrs
    }
}
