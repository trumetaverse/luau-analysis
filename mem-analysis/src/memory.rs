use crate::radare::{RadareMemoryInfo, RadareMemoryInfos};
use rangemap::RangeMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use serde;
use serde::Deserialize;
use std::collections::HashMap;

// use radare::{RadareMemoryInfo, RadareMemoryInfos};

// pub struct SourceMeta<'a>{
//     source_name: &'a str,
//     source_type: &'a str,
// }



// #[derive(Debug, Deserialize, Eq)]
#[derive(Debug, Eq, Deserialize, Clone)]
pub struct MemRange<'a> {
    pub vaddr_start: u64,
    pub paddr_start: u64,
    pub vsize: u64,
    pub size: u64,
    pub data: &'a [u8],
    pub perm: String,
    pub name: String,
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

impl<'a> PartialEq for MemRange<'a> {
    fn eq(&self, other: &Self) -> bool {
        // Equal if all key members are equal
        self.vaddr_start == other.vaddr_start &&
            self.paddr_start == other.paddr_start
    }
}

impl<'a> Display for MemRange<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} perms={} paddr={:08x} size={:08x} vaddr={:08x} vsize={:08x}",
            self.name, self.perm, self.paddr_start, self.size, self.vaddr_start, self.vsize
        )
    }
}

impl<'a> MemRange<'a> {
    pub fn from_radare_info(radare_info : &'a RadareMemoryInfo) -> Self{
        MemRange {
            vaddr_start: radare_info.vaddr,
            paddr_start: radare_info.paddr,
            vsize: radare_info.vsize,
            size: radare_info.size,
            data: &[0],
            perm: radare_info.perm.clone(),
            name: radare_info.name.clone(),
        }
    }

    pub fn new(
        perm: String,
        name: String,
        vaddr_start: u64,
        paddr_start: u64,
        vsize: u64,
        size: u64,
        data: &'a [u8],
    ) -> Self {
        MemRange {
            vaddr_start,
            paddr_start,
            vsize,
            size,
            data,
            perm: perm.clone(),
            name: name.clone(),
        }
    }
}

impl<'a> Memory for MemRange<'a> {
    fn vaddr_in_range(&self, addr: u64) -> bool {
        if self.vaddr_start <= addr && addr <= self.vaddr_start + self.vsize {
            return true;
        }
        return false;
    }

    fn paddr_in_range(&self, paddr: u64) -> bool {
        if self.paddr_start <= paddr && paddr <= self.paddr_start + self.size {
            return false;
        }
        return self.vaddr_in_range(self.get_vaddr_from_paddr(paddr).unwrap());
    }

    fn get_size(&self) -> u64 {
        return self.size;
    }

    fn get_vsize(&self) -> u64 {
        return self.vsize;
    }

    fn get_vbase_from_vaddr(&self, vaddr: u64) -> Option<u64> {
        if !self.vaddr_in_range(vaddr) {
            return None;
        }
        return Some(self.vaddr_start);
    }

    fn get_vbase_from_paddr(&self, paddr: u64) -> Option<u64> {
        if !self.paddr_in_range(paddr) {
            return None;
        }
        return Some(self.vaddr_start);
    }

    fn get_vaddr_from_paddr(&self, paddr: u64) -> Option<u64> {
        if !self.paddr_in_range(paddr) {
            return None;
        }
        let addr = (paddr - self.paddr_start) + self.vaddr_start;
        return Some(addr);
    }

    fn get_paddr_from_vaddr(&self, vaddr: u64) -> Option<u64> {
        if !self.vaddr_in_range(vaddr) {
            return None;
        }
        let addr = (vaddr - self.vaddr_start) + self.paddr_start;
        return Some(addr);
    }
}


#[derive(Debug, Clone)]
pub struct MemoryRanges<'a> {
    vmem_ranges: HashMap<u64, MemRange<'a>>,
    pmem_ranges: HashMap<u64, MemRange<'a>>,
    // pub vmem_ranges: RangeMap<u64, &'a MemRange<'a>>,
    // pub pmem_ranges: RangeMap<u64, &'a MemRange<'a>>,
}

// impl<'de: 'a> Deserialize<'de> for MemoryRanges<'a> {
//     /* ... */
// }

impl<'a> MemoryRanges<'a> {
    pub fn new() -> Self {
        // MemoryRanges{vmem_ranges: RangeMap::new(), pmem_ranges: RangeMap::new()}
        MemoryRanges{vmem_ranges: HashMap::new(), pmem_ranges: HashMap::new()}
    }

    pub fn add_mem_range(&mut self, mr : MemRange<'a>) -> () {
        // self.vmem_ranges.insert(mr.vaddr_start..mr.vaddr_start+mr.vsize, mr);
        // self.pmem_ranges.insert(mr.paddr_start..mr.paddr_start+mr.size, mr);

        self.vmem_ranges.insert(mr.vaddr_start, mr.clone());
        self.pmem_ranges.insert(mr.paddr_start, mr.clone());
    }

    pub fn get_paddr_range(&self, paddr: u64 ) -> Option<MemRange<'a>> {
        return self.pmem_ranges.get(&paddr).cloned();
    }

    pub fn get_vaddr_range(&self, vaddr: u64 ) -> Option<MemRange<'a>> {
        return self.vmem_ranges.get(&vaddr).cloned();
    }
    pub fn has_paddr(&self, paddr: u64 ) -> bool {
        return self.pmem_ranges.contains_key(&paddr);
    }

    pub fn has_vaddr(&self, vaddr: u64 ) -> bool {
        return self.vmem_ranges.contains_key(&vaddr);
    }

    pub fn from_radare_infos( radare : &'a RadareMemoryInfos) -> MemoryRanges<'a> {
        let mut mrs = MemoryRanges::new();

        for info in radare.items.iter() {
            let mut mr = MemRange::from_radare_info(info);
            mrs.add_mem_range(mr);
        }
        return mrs;
    }
}