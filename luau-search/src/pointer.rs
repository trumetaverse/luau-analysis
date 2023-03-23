use std::collections::HashMap;
use std::error::Error as StdErr;
// use multimap::MultiMap;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
// use serde::{Serialize};
// use std::fmt::{Display, Formatter, Result as FmtResult};
use log::{debug, info};

// use mem_analysis::memory::{MemRange};
use mem_analysis::data_interface::{DataInterface, ReadValue, ENDIAN};
// use mem_analysis::pointers::{PointerIndex, PointerRange};
use serde::Serialize;
use serde_json::json;

use crate::search::*;

impl Search for PointerSearch {
    fn search_buffer_next(
        &mut self,
        _buffer: &[u8],
        _pos: u64,
    ) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        panic!("Need to know base address for buffer");
    }
    fn search_buffer(&mut self, _buffer: &[u8]) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        panic!("Need to know base address for buffer");
    }
    fn search_buffer_with_bases(
        &mut self,
        buffer: &[u8],
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_buffer_with_bases(buffer, phys_base, virt_base);
    }
    fn search_interface(
        &mut self,
        di: &DataInterface,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_with_interface(di);
    }
    fn search_interface_with_bases(
        &mut self,
        di: &DataInterface,
        _phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_with_vaddr_start(di, virt_base);
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct Comment {
    pub search: String,
    pub paddr: u64,
    pub vaddr: u64,
    pub sink_vaddr: u64,
    pub sink_paddr: u64,
    pub sink_value: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PointerSearch {
    // pub ptr_ranges : Box<HashMap<u64, Box<PointerRange> >>,
    // pub ptr_lookup: Box<HashMap<u64, Box<PointerRange> >>,
    // pub valid_ranges: HashMap
    pub src_to_sinks: Box<HashMap<u64, u64>>,
    pub sink_values: Box<HashMap<u64, Option<u64>>>,
    pub start: Option<u64>,
    pub stop: Option<u64>,
    //pub offset_type: Option<OffsetType>,
    // pub base_vaddr: u64,
    // pub base_paddr: u64,
    // pub endian: ENDIAN,
    // pub page_size : u64,
    // pub page_mask : u64,
    // pub vaddr_alignment: u8, // in bytes on boundaries
    pub data_interface: Box<DataInterface>,
}

impl PointerSearch {
    pub fn perform_search_with_interface(
        &mut self,
        di: &DataInterface,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut search_results: Vec<Box<SearchResult>> = Vec::new();

        let v_mrs = self.data_interface.mem_ranges.get_mem_ranges();
        let mut wv_mrs = Vec::new();
        for mr in v_mrs.iter() {
            if mr.perm.find("w").is_some() {
                wv_mrs.push(mr.clone());
            }
        }

        for mr in wv_mrs.iter() {
            debug!(
            "Searching Memory Range: {} of {} for pointers from starting at vaddr {:08x} and paddr {:08x}.",
            mr.name, mr.vsize, mr.vaddr_start, mr.paddr_start
        );

            let vaddr: u64 = mr.vaddr_start;
            let _paddr: u64 = mr.paddr_start;
            let _size: u64 = mr.size;

            // let mut do_it = false;
            // let check_one = 0x3cc96270 as u64;
            // let check_two = 0x359a3d40 as u64;
            // let check_thre = 0x28a123a0 as u64;
            // if vaddr < check_one && check_one < vaddr + size {
            //     do_it = true;
            // } else if vaddr < check_two && check_two < vaddr + size {
            //     do_it = true;
            // } else if vaddr < check_thre && check_thre < vaddr + size {
            //     do_it = true;
            // }
            //
            // if !do_it {
            //     continue;
            // }
            let r_results = self.perform_search_with_vaddr_start(di, vaddr);
            let mut results: Vec<Box<SearchResult>> = r_results.unwrap();
            debug!(
                "Found {} results in {}, search_results.len() = {}.",
                results.len(),
                mr.name,
                search_results.len()
            );
            for r in results.iter_mut() {
                r.section_name = mr.name.clone();
            }
            search_results.append(&mut results);
        }
        info!("Found {} results.", search_results.len());
        return Ok(search_results);
    }
    pub fn perform_search_with_vaddr_start(
        &mut self,
        di: &DataInterface,
        svaddr: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut search_results: Vec<Box<SearchResult>> = Vec::new();
        let alignment: u64 = if di.vmem_info.alignment == 0 {
            1
        } else {
            di.vmem_info.alignment.into()
        };
        let incr = if di.vmem_info.word_sz == 0 {
            1
        } else {
            di.vmem_info.word_sz.into()
        };
        let page_mask = di.vmem_info.page_mask;

        let mut pos: u64 = 0;

        let o_vaddr_base = di.get_vaddr_base(&svaddr);
        if o_vaddr_base.is_none() {
            // debug!("Failed to find the range for vaddr: {:08x}", vaddr  );
            return Ok(search_results);
        }

        let phys_base = di.get_paddr_base_from_vaddr(&svaddr).unwrap();

        let o_end = di.get_vaddr_end(svaddr);
        if o_end.is_none() {
            return Ok(search_results);
        }
        let _end = o_end.unwrap();

        let virt_base = if svaddr != o_vaddr_base.unwrap() {
            svaddr % alignment
        } else {
            svaddr
        };
        // there may be a 0-sized buffer in which case there is nothing to return
        // so we need to accomodate the empty array gracefully here
        let o_vaddr_buf = di.shared_buffer_vaddr(virt_base);
        if o_vaddr_buf.is_none() {
            return Ok(search_results);
        }
        let vaddr_buf = o_vaddr_buf.unwrap();
        let endian = &di.vmem_info.endian;
        let read_value = |buffer: &[u8]| -> u64 {
            match endian {
                ENDIAN::BIG => match incr {
                    1 => <u8 as TryInto<u64>>::try_into(buffer[0]).unwrap() as u64,
                    2 => BigEndian::read_u16(buffer) as u64,
                    4 => BigEndian::read_u32(buffer) as u64,
                    8 => BigEndian::read_u64(buffer) as u64,
                    16 => BigEndian::read_u128(buffer) as u64,
                    _ => 0,
                },
                ENDIAN::LITTLE => match incr {
                    1 => buffer[0] as u64,
                    2 => LittleEndian::read_u16(buffer) as u64,
                    4 => LittleEndian::read_u32(buffer) as u64,
                    8 => LittleEndian::read_u64(buffer) as u64,
                    16 => LittleEndian::read_u128(buffer) as u64,
                    _ => 0,
                },
            }
        };

        while pos + incr - 1 < vaddr_buf.len() as u64 {
            let vaddr = pos + virt_base;
            let paddr = pos + phys_base;
            // debug!("Reading buffer at {:08x}", pos );

            let sink = read_value(&vaddr_buf[pos as usize..]);
            let sink_page = sink & page_mask;
            let lookup_has_page = di.vmem_info.ptr_lookup.contains_key(&sink_page);

            let has_alignment = sink % alignment == 0;

            if has_alignment && lookup_has_page {
                let sink_paddr = di.get_paddr_base_from_vaddr(&sink).unwrap();

                let _bal = di.vmem_info.ptr_lookup.get(&sink_page);
                // debug!("perform_search_buffer_with_bases: src: {:08x} sink {:08x} sink_page: *{:08x}", vaddr, sink, sink_page  );
                // {   // Update data interface pointer ranges
                //     let nm_ptr_range = _bal.unwrap();
                //     let mut ptr_range = nm_ptr_range.clone();
                //     ptr_range.add_vpointer(vaddr, sink);
                //     let ptr_range:&mut Arc<Box<PointerRange>> = &mut (.unwrap());
                // }
                self.src_to_sinks.insert(vaddr, sink);
                self.sink_values.insert(vaddr, Some(sink));
                let o_ptr_value = di.read_word_size_value_at_vaddr(sink);
                let o_sink_value = match o_ptr_value {
                    Some(x) => {
                        let value = x.value;
                        self.sink_values.insert(sink, Some(value));
                        if di.is_vaddr_ptr(value) {
                            self.src_to_sinks.insert(sink, value);
                        }
                        Some(value)
                    }
                    None => {
                        self.sink_values.insert(sink, None);
                        None
                    }
                };

                let comment = match o_sink_value {
                    Some(value) => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: Some(value),
                    },
                    // format!("sink_paddr:{:08x} *({:08x}):{:08x}", sink_paddr, sink, value),
                    None => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: None,
                    },
                    // format!("sink_paddr:{:08x} *({:08x}):{}", sink_paddr, sink, "INVALID"),
                };

                let mut sr = SearchResult::default();
                sr.boundary_offset = paddr as u64;
                sr.size = incr;
                sr.data = match o_sink_value {
                    Some(v) => Some(v.to_le_bytes().to_vec()),
                    None => None,
                };
                sr.vaddr = vaddr;
                sr.paddr = paddr;
                sr.section_name = match di.get_vaddr_section_name(vaddr) {
                    Some(s) => s.clone(),
                    None => "".to_string(),
                };
                sr.digest = "".to_string();
                sr.comment = json!(comment).to_string();
                // debug!("{}", sr.comment);
                let result = Box::new(sr);
                search_results.push(result);
            }
            pos += incr;
        }
        info!(
            "Found {} results in perform_search_buffer_with_bases: paddr: {:08x} vaddr: {:08x}",
            search_results.len(),
            phys_base,
            virt_base
        );
        return Ok(search_results.clone());
    }

    pub fn perform_search_buffer_with_bases(
        &mut self,
        buffer: &[u8],
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut search_results: Vec<Box<SearchResult>> = Vec::new();
        let alignment: u64 = if self.data_interface.vmem_info.alignment == 0 {
            1
        } else {
            self.data_interface.vmem_info.alignment.into()
        };
        let incr = if self.data_interface.vmem_info.word_sz == 0 {
            1
        } else {
            self.data_interface.vmem_info.word_sz.into()
        };
        let mut pos = 0;
        let end: u64 = buffer.len() as u64;
        let page_mask = self.data_interface.vmem_info.page_mask;

        while pos < end {
            let vaddr = pos + virt_base;
            let paddr = pos + phys_base;
            // debug!("Reading buffer at {:08x}", pos );
            let o_rvalue = self.data_interface.read_word_size_value_at_vaddr(vaddr);
            // debug!("Resulting value of read was {:#?}", o_rvalue  );
            if o_rvalue.is_none() {
                pos += incr;
                continue;
            }
            let rvalue: ReadValue = o_rvalue.unwrap();
            let sink = rvalue.value;
            let sink_page = sink & page_mask;
            let lookup_has_page = self
                .data_interface
                .vmem_info
                .ptr_lookup
                .contains_key(&sink_page);

            let has_alignment = sink % alignment == 0;
            // debug!("perform_search_buffer_with_bases: paddr: {:08x} @ pos {:08x} vaddr: *{:08x} = {:08x}", phys_base, pos, pos + virt_base, rvalue.value  );
            // debug!("perform_search_buffer_with_bases: lookup_has_page: {} has_alignment = {}", lookup_has_page, has_alignment  );
            // if self.is_pointer_with_alignment(&rvalue.value)
            if has_alignment && lookup_has_page {
                let sink_paddr = self
                    .data_interface
                    .get_paddr_base_from_vaddr(&sink)
                    .unwrap();
                let _bal = self.data_interface.vmem_info.ptr_lookup.get(&sink_page);
                // debug!("perform_search_buffer_with_bases: src: {:08x} sink {:08x} sink_page: *{:08x}", vaddr, sink, sink_page  );
                // {   // Update data interface pointer ranges
                //     let nm_ptr_range = _bal.unwrap();
                //     let mut ptr_range = nm_ptr_range.clone();
                //     ptr_range.add_vpointer(vaddr, sink);
                // }
                // let ptr_range:&mut Arc<Box<PointerRange>> = &mut (.unwrap());
                self.src_to_sinks.insert(vaddr, sink);
                self.sink_values.insert(vaddr, Some(sink));
                let o_ptr_value = self.data_interface.read_word_size_value_at_vaddr(sink);
                let o_sink_value = match o_ptr_value {
                    Some(x) => {
                        let value = x.value;
                        self.sink_values.insert(sink, Some(value));
                        if self.data_interface.is_vaddr_ptr(value) {
                            self.src_to_sinks.insert(sink, value);
                        }
                        Some(value)
                    }
                    None => {
                        self.sink_values.insert(sink, None);
                        None
                    }
                };

                let comment = match o_sink_value {
                    Some(value) => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: Some(value),
                    },
                    // format!("sink_paddr:{:08x} *({:08x}):{:08x}", sink_paddr, sink, value),
                    None => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: None,
                    },
                    // format!("sink_paddr:{:08x} *({:08x}):{}", sink_paddr, sink, "INVALID"),
                };

                let mut sr = SearchResult::default();
                sr.boundary_offset = paddr as u64;
                sr.size = incr;
                sr.data = match o_sink_value {
                    Some(v) => Some(v.to_le_bytes().to_vec()),
                    None => None,
                };
                sr.vaddr = vaddr;
                sr.paddr = paddr;
                sr.section_name = match self.data_interface.get_vaddr_section_name(vaddr) {
                    Some(s) => s.clone(),
                    None => "".to_string(),
                };
                sr.digest = "".to_string();
                sr.comment = json!(&comment).to_string();
                // debug!("{}", sr.comment);
                let result = Box::new(sr);
                search_results.push(result);
            }
            pos += incr;
        }
        info!(
            "Found {} results in perform_search_buffer_with_bases: paddr: {:08x} vaddr: {:08x}",
            search_results.len(),
            phys_base,
            virt_base
        );

        return Ok(search_results.clone());
    }

    pub fn new(start: Option<u64>, stop: Option<u64>, data_interface: Box<DataInterface>) -> Self {
        PointerSearch {
            start: start.clone(),
            stop: stop.clone(),
            // base_paddr: base_paddr,
            // base_vaddr: base_vaddr,
            //offset_type: None,
            src_to_sinks: Box::new(HashMap::new()),
            sink_values: Box::new(HashMap::new()),
            data_interface: data_interface,
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

    // pub fn add_mem_range(&mut self, mr : &MemRange) -> bool {
    //     let cpage = mr.vaddr_start & self.page_mask;
    //     if self.contains_pointer_range(&cpage) {
    //         return false;
    //     }
    //     debug!("MemRange {} does not exist, creating.", mr);
    //     self.create_pointer_range(mr.paddr_start, mr.vaddr_start, mr.size);
    //     debug!("MemRange {} does not exist, creating.", mr);
    //     return true;
    // }
    //
    // pub fn add_mem_ranges(&mut self, mem_ranges: &Vec<MemRange>) -> bool {
    //     // let mrs = mem_ranges.get_mem_ranges();
    //     debug!("Creating pointer ranges from {} mem_ranges.", mem_ranges.len());
    //     for mr in mem_ranges.iter() {
    //         self.add_mem_range(mr);
    //     }
    //     return true;
    // }
    //
    // pub fn add_box_mem_ranges(&mut self, mem_ranges: &Vec<Box<MemRange>>) -> bool {
    //     // let mrs = mem_ranges.get_mem_ranges();
    //     debug!("Creating pointer ranges from {} mem_ranges.", mem_ranges.len());
    //     for mr in mem_ranges.iter() {
    //         self.add_mem_range(&*mr);
    //     }
    //     return true;
    // }
}
