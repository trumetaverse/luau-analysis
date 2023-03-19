use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::error::Error as StdErr;
use rangemap::RangeMap;
use multimap::MultiMap;
use byteorder::{ByteOrder, LittleEndian, BigEndian};
use std::borrow::BorrowMut;
use serde::{Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use log::{debug };//, info, error};

use mem_analysis::memory::{MemRange, MemRanges};


use crate::search::*;


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

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum ENDIAN {
    BIG,
    LITTLE
}

#[derive(Debug, PartialEq, Clone, Eq, Serialize)]
pub struct PointerRange {
    pub pstart : u64,
    pub pend : u64,

    pub vstart : u64,
    pub vend : u64,

    pub pointer_index: PointerIndex,
}

impl PointerRange {
    pub fn new(pstart : u64, pend : u64, vstart : u64, vend : u64) -> Self {
        assert_eq!(vstart <= vend, true);
        assert_eq!(pstart <= pend, true);
        PointerRange {pstart, pend, vstart, vend, pointer_index: PointerIndex::new() }
    }

    pub fn in_vrange(&self, val : u64) -> bool {
        return self.vstart <= val && val < self.vend;
    }

    pub fn in_prange(&self, val : u64) -> bool {
        return self.pstart <= val && val < self.pend;
    }

    pub fn in_range(&self, val : u64) -> bool {
        return self.in_vrange(val) || self.in_prange(val);
    }

    pub fn vsize(&self) -> u64 {
        return self.vend - self.vstart ;
    }

    pub fn psize(&self) -> u64 {
        return self.pend - self.pstart ;
    }

    pub fn add_vpointer(&mut self, source : u64, sink : u64) -> bool {
        let mut added = false;
        if self.in_vrange(sink) {
            self.pointer_index.add_sink(source, sink);
            added = true;
        }
        if self.in_vrange(source) {
            self.pointer_index.add_source(source, sink);
            added = true;
        }
        return added;

    }
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

impl Search for PointerSearch {
    fn search_buffer_next(&mut self, buffer: &[u8], pos: u64) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        panic!("Need to know base address for buffer");
    }
    fn search_buffer(&mut self, buffer: &[u8]) -> Result<Vec<SearchResult>, Box<dyn StdErr>> {
        panic!("Need to know base address for buffer");
    }
    fn search_buffer_with_bases(&mut self, buffer: &[u8], phys_base: u64, virt_base : u64) -> Result<Vec<SearchResult>, Box<dyn StdErr>> {
        return self.perform_search_buffer_with_bases(buffer, phys_base, virt_base);
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PointerSearch {

    pub ptr_ranges : Box<HashMap<u64, Box<PointerRange> >>,
    pub ptr_lookup: Box<HashMap<u64, Box<PointerRange> >>,
    // pub valid_ranges: HashMap
    pub start: Option<u64>,
    pub stop: Option<u64>,
    //pub offset_type: Option<OffsetType>,
    // pub base_vaddr: u64,
    // pub base_paddr: u64,
    pub word_sz : u8,
    pub endian: ENDIAN,
    pub page_size : u64,
    pub page_mask : u64,
    pub vaddr_alignment: u8,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ReadValue {
    consumed : u8,
    value : u64,
}

impl PointerSearch {

    pub fn perform_search_buffer_with_bases(&mut self, buffer: &[u8], phys_base: u64, virt_base : u64) -> Result<Vec<SearchResult>, Box<dyn StdErr>> {

        let incr : u64 = if self.vaddr_alignment == 0 {1} else {self.vaddr_alignment.into()};
        let mut pos = 0;
        let end:u64 = buffer.len() as u64;

        let mut search_results = Vec::new();
        while pos < end {
            let slize : usize = pos as usize;
            let o_rvalue = self.read_value(&buffer[slize ..]);

            if o_rvalue.is_none() {
                break;
            }

            let rvalue : ReadValue = o_rvalue.unwrap();
            if self.is_pointer(&rvalue.value)
            {
                let sink = rvalue.value;
                let vaddr = pos + virt_base;
                let paddr = pos + phys_base;
                let _bal = self.ptr_lookup.get(&sink);
                let nm_ptr_range = _bal.unwrap();
                let mut ptr_range = nm_ptr_range.clone();

                // let ptr_range:&mut Arc<Box<PointerRange>> = &mut (.unwrap());
                ptr_range.add_vpointer(vaddr, sink);
                let result = SearchResult {
                    boundary_offset: paddr as u64,
                    size: incr,
                    // data: rdata,
                    start_pattern: format!("{:08x}", vaddr),
                    end_pattern: format!("{:08x}", sink),
                    vaddr: vaddr,
                    paddr: paddr,
                    section_name: "".to_string(),
                    digest: "".to_string(),
                };
                search_results.push(result);
            }
            pos += incr;
        }
        return Ok(search_results);


    }

    pub fn can_read(&self, buffer : &[u8], pos : u64 ) -> bool {
        return (buffer.len() as u64) < (pos + self.word_sz as u64);
    }

    pub fn read_value(&self, buffer : &[u8]) -> Option<ReadValue> {

        if !self.can_read(buffer, 0) {
            return None;
        }

        let value : Option<u64> = match self.endian {
            ENDIAN::BIG => {
                match self.word_sz {
                    16 => Some(BigEndian::read_u16(buffer) as u64),
                    32 => Some(0 as u64),
                    64 => Some(0 as u64),
                    _ => None,
                }
            },
            ENDIAN::LITTLE => {
                match self.word_sz {
                    16 => Some(LittleEndian::read_u16(buffer)  as u64),
                    32 => Some(0 as u64),
                    64 => Some(0 as u64),
                    _ => None,
                }
            }

        };

        if value.is_some() {
            return  Some(ReadValue{consumed: self.word_sz, value: value.unwrap()})
        }
        return None;
    }

    pub fn read_value_at(&self, buffer : &[u8], pos : u64) -> Option<ReadValue> {
        return self.read_value(&buffer[ pos as usize .. ]);
    }

    pub fn new(start : Option<u64>,
               stop : Option<u64>,
               word_sz : Option<u8>,
               endian : Option<ENDIAN>,
               vaddr_alignment: Option<u8>,
               o_ptr_ranges : Option<Box<HashMap<u64, Box<PointerRange> >>>,
               o_ptr_lookup : Option<Box<HashMap<u64, Box<PointerRange> >>>)-> Self {

        let ptr_ranges = match o_ptr_ranges {
            Some(ptr_ranges) => ptr_ranges.clone(),
            None => Box::new(HashMap::new())
        };
        let ptr_lookup = match o_ptr_lookup {
            Some(ptr_lookup) => ptr_lookup.clone(),
            None => Box::new(HashMap::new())
        };

        let mword_sz : u8 = match word_sz {
            Some(v) => match v  {
                16 => 16,
                32 => 32,
                64 => 64,
                _ => 32,
            },
            None => 32,
        };

        let alignment : u8 = match vaddr_alignment {
            Some(a) => match a  {
                0 => 0,
                4 => 4,
                8 => 8,
                16 => 16,
                32 => 32,
                64 => 64,
                _ => mword_sz,
            },
            None => mword_sz,
        };
        PointerSearch {
            start: start.clone(),
            stop : stop.clone(),
            // base_paddr: base_paddr,
            // base_vaddr: base_vaddr,
            //offset_type: None,
            // src_addrs: src_addrs.clone(),
            // sink_addrs: sink_addrs.clone(),
            word_sz: mword_sz,
            endian: match endian {
                Some(v) => v,
                None => ENDIAN::LITTLE
            },
            ptr_ranges: ptr_ranges,
            ptr_lookup: ptr_lookup,
            page_mask : 0xfffffffffffff000 as u64,
            page_size : 4096 as u64,
            vaddr_alignment: alignment
        }
    }

    // pub fn add_range_existing(&mut self, start_vaddr: u64, end_vaddr: u64, range_srcs : Arc<Box<RangePointer>>, range_sinks : Arc<Box<RangePointer>>) -> bool {
    //     // let end = start_vaddr + end_vaddr;
    //     self.src_addrs.insert(start_vaddr.. end_vaddr, range_srcs.clone());
    //     self.sink_addrs.insert(start_vaddr.. end_vaddr, range_sinks.clone());
    //     return true;
    // }

    // pub fn add_existing_srcs_vec(&mut self, start_vaddr: u64, end_vaddr: u64, range_srcs : Arc<Box<RangePointer>>, range_sinks : Arc<Box<RangePointer>>) -> bool {
    //     // let end = start_vaddr + end_vaddr;
    //     self.src_addrs.insert(start_vaddr.. end_vaddr, range_srcs.clone());
    //     self.sink_addrs.insert(start_vaddr.. end_vaddr, range_sinks.clone());
    //     return true;
    // }

    // pub fn add_range(&mut self, start_vaddr: u64, end_vaddr:u64) -> bool {
    //     let r_sinks = Arc::new(Box::new(RangePointer::new()));
    //     let r_srcs = Arc::new(Box::new(RangePointer::new(start_vaddr, end_vaddr)));
    //     return self.add_range_existing(start_vaddr, end_vaddr, r_srcs, r_sinks);
    // }

    pub fn is_pointer(&self, vaddr : &u64 ) -> bool {
        return self.contains_pointer_range(vaddr);
    }

    pub fn contains_pointer_range(&self, vaddr : &u64 ) -> bool {
        let mut cpage = vaddr & self.page_mask;
        if self.ptr_ranges.contains_key(&cpage) {
            return true;
        }
        return self.ptr_lookup.contains_key(&cpage);
    }

    pub fn get_pointer_range_by_vaddr(&self, vaddr : u64 ) -> Option<Box<PointerRange>> {
        let mut cpage = vaddr & self.page_mask;
        if !self.contains_pointer_range(&cpage) {
            return None;
        }
        return Some(self.ptr_lookup.get(&cpage).unwrap().clone());
    }

    pub fn create_pointer_range(&mut self, paddr : u64, vaddr: u64, size : u64) -> Box<PointerRange> {
        debug!("Creating a pointer range for paddr: {:08x} vaddr: {:08x} of size: {:08x}", paddr, vaddr, size);
        let ptr_range = Box::new(PointerRange::new(paddr, paddr + size, vaddr, vaddr + size ));
        let mut cpage = vaddr & self.page_mask;
        self.add_pointer_range(ptr_range.clone());
        return ptr_range.clone();
    }

    pub fn add_pointer_range(&mut self, ptr_range : Box<PointerRange>) -> bool {
        let mut cpage = ptr_range.vstart & self.page_mask;

        if self.ptr_ranges.contains_key(&cpage) {
           return false;
        }
        debug!("Adding the pointer range: {:08x} for {:08x}", ptr_range.vstart, cpage);
        self.ptr_ranges.insert(cpage, ptr_range.clone());

        let vaddr_end = ptr_range.vend;
        debug!("Updating the lookup cache: {:08x} for {:08x}", ptr_range.vstart, cpage);
        while cpage < vaddr_end {
            self.ptr_lookup.insert(cpage, ptr_range.clone());
            cpage = (self.page_size + cpage) & self.page_mask
        }
        debug!("Done updating the lookup cache: {:08x} with a len() : {:08x}", ptr_range.vstart, self.ptr_lookup.len());
        return true;
    }

    pub fn add_mem_range(&mut self, mr : &MemRange) -> bool {
        let cpage = mr.vaddr_start & self.page_mask;
        if self.contains_pointer_range(&cpage) {
            return false;
        }
        debug!("MemRange {} does not exist, creating.", mr);
        self.create_pointer_range(mr.paddr_start, mr.vaddr_start, mr.size);
        debug!("MemRange {} does not exist, creating.", mr);
        return true;
    }

    pub fn add_mem_ranges(&mut self, mem_ranges: &Vec<MemRange>) -> bool {
        // let mrs = mem_ranges.get_mem_ranges();
        debug!("Creating pointer ranges from {} mem_ranges.", mem_ranges.len());
        for mr in mem_ranges.iter() {
            self.add_mem_range(mr);
        }
        return true;
    }

    pub fn get_pointer_range_vec(&self) -> Vec<Box<PointerRange>> {
        let mut v_ranges = Vec::new();
        for (_key, pr) in self.ptr_ranges.iter() {
            v_ranges.push(pr.clone());
        }
        return v_ranges;
    }

}