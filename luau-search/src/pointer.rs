use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::{File};
use std::path::{PathBuf};
use std::io::{BufWriter, Write};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error as StdErr;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use log::{debug, info, error};
use std::sync::{Arc, RwLock};
use chrono::{Utc, Duration};

use serde_json::json;
use serde::ser::{Serialize, Serializer, SerializeMap};

use std::thread;
use mem_analysis::memory::{MemRange};
use mem_analysis::data_interface::{DataInterface, ReadValue, ENDIAN};

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
        di: Arc<RwLock<Box<DataInterface>>>,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_with_interface_mt(di);
    }
    fn search_interface_with_bases(
        &mut self,
        di: Arc<RwLock<Box<DataInterface>>>,
        _phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_with_vaddr_start(di, virt_base);
    }
}


#[derive(Debug, PartialEq, Clone)]
pub struct Comment {
    pub search: String,
    pub paddr: u64,
    pub vaddr: u64,
    pub paddr_base: u64,
    pub vaddr_base: u64,
    pub sink_vaddr: u64,
    pub sink_paddr: u64,
    pub sink_vaddr_base: u64,
    pub sink_paddr_base: u64,
    pub sink_value: Option<u64>,
}

impl Serialize for Comment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("search", &self.search)?;
        map.serialize_entry("paddr", &format!("{:08x}", self.paddr))?;
        map.serialize_entry("paddr_base", &format!("{:08x}", self.paddr_base))?;
        map.serialize_entry("vaddr", &format!("{:08x}", self.vaddr))?;
        map.serialize_entry("vaddr_base", &format!("{:08x}", self.vaddr_base))?;
        map.serialize_entry("sink_vaddr", &format!("{:08x}", self.sink_vaddr))?;
        map.serialize_entry("sink_paddr", &format!("{:08x}", self.sink_paddr))?;
        map.serialize_entry("sink_vaddr_base", &format!("{:08x}", self.sink_vaddr_base))?;
        map.serialize_entry("sink_paddr_base", &format!("{:08x}", self.sink_paddr_base))?;
        if self.sink_value.is_some() {
            map.serialize_entry("sink_value", &format!("{:08x}", self.sink_value.unwrap() ))?;
        } else {
            map.serialize_entry("sink_value", "null")?;
        }

        map.end()
    }
}

impl Display for Comment {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {

        let mut sv = "null".to_string();
        if self.sink_value.is_some() {
            sv = format!("{:08x}", self.sink_value.unwrap());
        }

        write!(
            f,
            "{{\"{}\":\"{}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{:08x}\", \"{}\":\"{}\"\
        }}",
            "search", &self.search,
            "paddr", self.paddr,
            "paddr_base", self.paddr_base,
            "vaddr", self.vaddr,
            "vaddr_base", self.vaddr_base,
            "sink_vaddr", self.sink_vaddr,
            "sink_paddr", self.sink_paddr,
            "sink_vaddr_base", self.sink_vaddr_base,
            "sink_paddr_base", self.sink_paddr_base,
            "sink_value", sv
        )
    }
}

#[derive(Debug, Clone)]
pub struct PointerSearch {
    pub src_to_sinks: Box<HashMap<u64, u64>>,
    pub sink_values: Box<HashMap<u64, Option<u64>>>,
    pub start: Option<u64>,
    pub stop: Option<u64>,
    pub data_interface: Arc<RwLock<Box<DataInterface>>>,
    pub comments : Box<BTreeMap<u64, Box<Comment>>>,
    pub shared_comments : Arc<RwLock<Box<BTreeMap<u64, Box<Comment>>>>>,
    pub max_threads: u64,
}

pub fn perform_search_with_vaddr_start(
    di_arw: Arc<RwLock<Box<DataInterface>>>,
    mr: &Box<MemRange>,
    shared_results : Arc<RwLock<Vec<Box<SearchResult>>>>,
    shared_comments: Arc<RwLock<Box<BTreeMap<u64, Box<Comment>>>>>,
) -> Result<(), Box<dyn StdErr>> {
    let di = di_arw.read().unwrap();
    let svaddr: u64 = mr.vaddr_start;
    let mut found = 0 as u64;
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
        return Ok(());
    }

    let phys_base = di.get_paddr_base_from_vaddr(&svaddr).unwrap();

    let o_end = di.get_vaddr_end(svaddr);
    if o_end.is_none() {
        return Ok(());
    }
    let _end = o_end.unwrap();
    let vaddr_base = o_vaddr_base.unwrap();
    let virt_base = if svaddr != vaddr_base {
        svaddr % alignment
    } else {
        svaddr
    };
    let o_vaddr_buf = di.shared_buffer_vaddr(virt_base);
    if o_vaddr_buf.is_none() {
        return Ok(());
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
        let sink = read_value(&vaddr_buf[pos as usize..]);
        let sink_page = sink & page_mask;
        let lookup_has_page = di.vmem_info.ptr_lookup.contains_key(&sink_page);

        if lookup_has_page {
            let sink_paddr = di.convert_vaddr_to_paddr(&sink).unwrap();
            let sink_paddr_base = di.get_paddr_base_from_vaddr(&sink).unwrap();
            let sink_vaddr_base = di.get_vaddr_base_from_vaddr(&sink).unwrap();

            let _bal = di.vmem_info.ptr_lookup.get(&sink_page);
            let o_ptr_value = di.read_word_size_value_at_vaddr(sink);
            let o_sink_value = match o_ptr_value {
                Some(x) => {
                    let value = x.value;
                    Some(value)
                }
                None => {
                    None
                }
            };

            let i_comment = match o_sink_value {
                Some(value) => Box::new(Comment {
                    search: "pointer_search".to_string(),
                    vaddr: vaddr,
                    paddr: paddr,
                    sink_paddr: sink_paddr,
                    sink_vaddr: sink,
                    sink_value: Some(value),
                    sink_vaddr_base: sink_vaddr_base,
                    sink_paddr_base: sink_paddr_base,
                    paddr_base: phys_base,
                    vaddr_base: vaddr_base
                }),
                None => Box::new(Comment {
                    search: "pointer_search".to_string(),
                    vaddr: vaddr,
                    paddr: paddr,
                    sink_paddr: sink_paddr,
                    sink_vaddr: sink,
                    sink_value: None,
                    sink_vaddr_base: sink_vaddr_base,
                    sink_paddr_base: sink_paddr_base,
                    paddr_base: phys_base,
                    vaddr_base: vaddr_base
                }),
            };

            let mut sr = Box::new(SearchResult::default());
            sr.boundary_offset = paddr as u64;
            sr.size = incr;
            sr.vaddr = vaddr;
            sr.paddr = paddr;
            sr.digest = "".to_string();
            sr.section_name = mr.name.clone();
            shared_comments.write().unwrap().insert(vaddr, i_comment);
            shared_results.write().unwrap().push(sr);
            found += 1;
        }
        pos += incr;
    }
    info!(
            "Found {} results in perform_search_buffer_with_bases: paddr: {:08x} vaddr: {:08x} name: {}, total comments: {}, total results: {}",
            found,
            phys_base,
            virt_base,
            mr.name,
            shared_comments.read().unwrap().len(),
            shared_results.read().unwrap().len()
        );
    return Ok(());
}

impl PointerSearch {

    pub fn perform_search_with_interface_mt(
        &mut self,
        di_arw: Arc<RwLock<Box<DataInterface>>>,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut thread_handles_ac: VecDeque<thread::JoinHandle<()>> = VecDeque::new();
        let shared_results : Arc<RwLock<Vec<Box<SearchResult>>>> = Arc::new(RwLock::new(Vec::new()));
        let shared_comments = Arc::clone(&self.shared_comments);
        let di = di_arw.read().unwrap();

        let v_mrs = di.mem_ranges.get_mem_ranges();
        let mut wv_mrs = Vec::new();
        for mr in v_mrs.iter() {
            if mr.perm.find("w").is_some() {
                wv_mrs.push(mr.clone());
            }
        }
        let max_threads = self.max_threads.clone() as usize;
        for mr in wv_mrs.iter() {
            let bsr = Arc::clone(&shared_results);
            let bsc = Arc::clone(&shared_comments);
            let bmr = mr.clone();
            let cdi = di_arw.clone();
            let t = thread::spawn(move || {
                let _ = perform_search_with_vaddr_start(cdi.clone(), &bmr, bsr.clone(), bsc.clone());
            });
            thread_handles_ac.push_back(t);
            debug!(
            "Searching Memory Range: {} of {} for pointers from starting at vaddr {:08x} and paddr {:08x}.",
            mr.name, mr.vsize, mr.vaddr_start, mr.paddr_start);
            // this loop structure is used to relieve memory pressure and ensure too many threads
            // are not created at once.  I had a hard time using the thread pool to help men manage
            // this
            while thread_handles_ac.len() > max_threads {
                let mut dt_enter = Utc::now();
                let dt_exit = dt_enter.checked_add_signed(Duration::milliseconds(500)).unwrap();
                // Join as many threads as we can in 500 ms
                while dt_enter < dt_exit && thread_handles_ac.len() > 0{
                    let at = thread_handles_ac.pop_front().unwrap();
                    // debug!("joining the threas.");
                    let _ = at.join();
                    // debug!("joining the threas.");
                    dt_enter = Utc::now();
                }
                // want to push down the number of running threads further. Join as many threads as
                // we can in the next 500 ms (not a sophisticated strategy)
                if thread_handles_ac.len() > 0 && thread_handles_ac.len() > max_threads - 5{
                    let mut dt_enter = Utc::now();
                    let dt_exit = dt_enter.checked_add_signed(Duration::milliseconds(500)).unwrap();
                    while dt_enter < dt_exit && thread_handles_ac.len() > 0{
                        let at = thread_handles_ac.pop_front().unwrap();
                        let _ = at.join();
                        dt_enter = Utc::now();
                    }
                }
            }
        }

        thread_handles_ac
            .into_iter()
            .for_each(|th| th.join().expect("can't join thread"));

        let lshared_results = Arc::try_unwrap(shared_results).expect("lock still has owners");
        let search_results = lshared_results.into_inner().expect("Mutex cannot be locked");
        info!("Found {} results.", search_results.len());
        info!("Found {} shared_comments.", shared_comments.read().unwrap().len());
        info!("Found {} self.shared_comments.", shared_comments.read().unwrap().len());
        return Ok(search_results);
    }
    pub fn perform_search_with_interface(
        &mut self,
        di_arw: Arc<RwLock<Box<DataInterface>>>,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut search_results: Vec<Box<SearchResult>> = Vec::new();
        let di = di_arw.read().unwrap();
        let v_mrs = di.mem_ranges.get_mem_ranges();
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

            let r_results = self.perform_search_with_vaddr_start(di_arw.clone(), vaddr);
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
        di_arw: Arc<RwLock<Box<DataInterface>>>,
        svaddr: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let di = di_arw.read().unwrap();
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
            return Ok(search_results);
        }

        let phys_base = di.get_paddr_base_from_vaddr(&svaddr).unwrap();

        let o_end = di.get_vaddr_end(svaddr);
        if o_end.is_none() {
            return Ok(search_results);
        }
        let _end = o_end.unwrap();
        let vaddr_base = o_vaddr_base.unwrap();
        let virt_base = if svaddr != vaddr_base {
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
                let sink_paddr = di.convert_vaddr_to_paddr(&sink).unwrap();
                let sink_paddr_base = di.get_paddr_base_from_vaddr(&sink).unwrap();
                let sink_vaddr_base = di.get_vaddr_base_from_vaddr(&sink).unwrap();

                let _bal = di.vmem_info.ptr_lookup.get(&sink_page);
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

                let i_comment = match o_sink_value {
                    Some(value) => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: Some(value),
                        sink_vaddr_base: sink_vaddr_base,
                        sink_paddr_base: sink_paddr_base,
                        paddr_base: phys_base,
                        vaddr_base: vaddr_base
                    },
                    None => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: None,
                        sink_vaddr_base: sink_vaddr_base,
                        sink_paddr_base: sink_paddr_base,
                        paddr_base: phys_base,
                        vaddr_base: vaddr_base
                    },
                };

                let comment = Box::new(i_comment);
                self.comments.insert(vaddr, comment.clone());

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
        let di = self.data_interface.read().unwrap();
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
        let mut pos = 0;
        let end: u64 = buffer.len() as u64;
        let page_mask = di.vmem_info.page_mask;
        let vaddr_base = di.get_vaddr_base_from_vaddr(&virt_base).unwrap();
        let paddr_base = di.get_paddr_base_from_vaddr(&virt_base).unwrap();

        while pos < end {
            let vaddr = pos + virt_base;
            let paddr = pos + phys_base;
            let o_rvalue = di.read_word_size_value_at_vaddr(vaddr);
            if o_rvalue.is_none() {
                pos += incr;
                continue;
            }
            let rvalue: ReadValue = o_rvalue.unwrap();
            let sink = rvalue.value;
            let sink_page = sink & page_mask;
            let lookup_has_page = di.vmem_info.ptr_lookup.contains_key(&sink_page);

            let has_alignment = sink % alignment == 0;
            if has_alignment && lookup_has_page {
                let sink_paddr = di.convert_vaddr_to_paddr(&sink).unwrap();
                let sink_paddr_base = di.get_paddr_base_from_vaddr(&sink).unwrap();
                let sink_vaddr_base = di.get_vaddr_base_from_vaddr(&sink).unwrap();
                let _bal = di.vmem_info.ptr_lookup.get(&sink_page);
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

                let i_comment = match o_sink_value {
                    Some(value) => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: Some(value),
                        sink_vaddr_base: sink_vaddr_base,
                        sink_paddr_base: sink_paddr_base,
                        paddr_base: paddr_base,
                        vaddr_base: vaddr_base
                    },
                    None => Comment {
                        search: "pointer_search".to_string(),
                        vaddr: vaddr,
                        paddr: paddr,
                        sink_paddr: sink_paddr,
                        sink_vaddr: sink,
                        sink_value: None,
                        sink_vaddr_base: sink_vaddr_base,
                        sink_paddr_base: sink_paddr_base,
                        paddr_base: paddr_base,
                        vaddr_base: vaddr_base
                    },
                };

                let comment = Box::new(i_comment);
                self.comments.insert(vaddr, comment.clone());

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
                self.comments.insert(vaddr, comment.clone());
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

    pub fn new(start: Option<u64>, stop: Option<u64>, data_interface: Arc<RwLock<Box<DataInterface>>>) -> Self {
        PointerSearch {
            start: start.clone(),
            stop: stop.clone(),
            src_to_sinks: Box::new(HashMap::new()),
            sink_values: Box::new(HashMap::new()),
            data_interface: data_interface.clone(),
            comments: Box::new(BTreeMap::new()),
            shared_comments: Arc::new(RwLock::new(Box::new(BTreeMap::new()))),
            max_threads: 30,
        }
    }

    pub fn get_comments(&self) -> Vec<Box<Comment>> {
        let mut comments = Vec::new();
        for (_, c) in self.shared_comments.read().unwrap().iter() {
            comments.push(c.clone())
        }
        return comments;
    }

    pub fn write_comments(&self, output_filename: PathBuf ) -> () {
        let capacity = 1000 * 1024 * 1024;
        let o_writer = File::create(&output_filename);
        let mut writer = match o_writer {
            Ok(file) => BufWriter::with_capacity(capacity, file),
            Err(err) => {
                let msg = format!(
                    "Failed to open file: {}. {} ",
                    output_filename.display(),
                    err
                );
                error!("{}", msg);
                panic!("{}", msg);
            }
        };
        let msg = format!(
            "Writing out the shared comments",
        );
        debug!("{}", msg);

        let sc = self.shared_comments.read().unwrap();
        let msg = format!(
            "Writing {} results to file: {}", sc.len(), output_filename.display()
        );
        info!("{}", msg);
        let mut lines_written = 0;
        for (_, c) in sc.iter() {
            lines_written += 1;
            if lines_written % 100000 == 0 {
                info!("Wrote {} results", lines_written);
            }

            match writeln!(writer, "{}", json!(c).to_string()) {
                Ok(_) => {}
                Err(err) => {
                    let msg = format!(
                        "Failed to write data to: {}. {} ",
                        output_filename.display(),
                        err
                    );
                    error!("{}", msg);
                    panic!("{}", msg);
                }
            };
        }
        writer.flush().unwrap();
    }
}
