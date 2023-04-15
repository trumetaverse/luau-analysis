use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error as StdErr;
use bincode;
use bincode::deserialize;
use bincode::config::{Options};
// use multimap::MultiMap;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
// use serde::{Serialize};
// use std::fmt::{Display, Formatter, Result as FmtResult};
use log::{debug, info};

// use mem_analysis::memory::{MemRange};
use mem_analysis::data_interface::{DataInterface, ReadValue, ENDIAN};
// use mem_analysis::pointers::{PointerIndex, PointerRange};
use serde_json::json;
use serde::ser::{Serialize, Serializer, SerializeMap};
use serde::Deserialize;

use diesel::{Queryable, Selectable};

use crate::search::*;

impl Search for LuaPageSearch {
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


// #[derive(Debug, PartialEq, Clone, Queryable, Selectable)]
// #[diesel(table_name = "pointer_results")]
#[derive(Debug, PartialEq, Clone)]
pub struct Comment {
    pub search: String,
    pub paddr: u64,
    pub vaddr: u64,
    pub paddr_base: u64,
    pub vaddr_base: u64,

    pub prev: u64,
    pub next: u64,
    pub gcolistprev: u64,
    pub gcolistnext: u64,
    pub freelist: u64,

    pub block_size: u32,
    pub page_size: u32,
    pub free_next: i32,
    pub busy_blocks: u32,
}

impl Serialize for Comment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("search", "lua_pages")?;
        map.serialize_entry("paddr", &format!("{:08x}", self.paddr))?;
        map.serialize_entry("paddr_base", &format!("{:08x}", self.paddr_base))?;
        map.serialize_entry("vaddr", &format!("{:08x}", self.vaddr))?;
        map.serialize_entry("vaddr_base", &format!("{:08x}", self.vaddr_base))?;

        map.serialize_entry("prev", &format!("{:08x}", self.prev))?;
        map.serialize_entry("next", &format!("{:08x}", self.next))?;
        map.serialize_entry("gcolistprev", &format!("{:08x}", self.gcolistprev))?;
        map.serialize_entry("gcolistnext", &format!("{:08x}", self.gcolistnext))?;
        map.serialize_entry("freelist", &format!("{:08x}", self.freelist))?;

        map.serialize_entry("block_size", &format!("{:08x}", self.block_size))?;
        map.serialize_entry("page_size", &format!("{:08x}", self.page_size))?;
        map.serialize_entry("busy_blocks", &format!("{:08x}", self.busy_blocks))?;
        map.serialize_entry("free_next", &format!("{:08x}", self.free_next))?;

        map.end()
    }
}

trait LuaPage : Sized {
    fn load(buffer: &[u8], di: &DataInterface) -> Result<Self, dyn StdErr> where Self: Sized;
    fn get_prev(&self) -> u64;
    fn get_next(&self) -> u64;
    fn get_gcolistprev(&self) -> u64;
    fn get_gcolistnext(&self) -> u64;
    fn get_page_size(&self) -> i32;
    fn get_block_size(&self) -> i32;
    fn get_free_list(&self) -> u64;
    fn get_free_next(&self) -> u64;
    fn get_busy_blocks(&self) -> i32;

    fn get_size(word_sz : u8) -> u64 {
        match word_sz {
            8 => std::mem::size_of::<LuaPageX64>() as u64,
            4 => std::mem::size_of::<LuaPageX32>() as u64,
            _ => std::mem::size_of::<LuaPageX32>() as u64,
        }
    }

    fn get_x32_size() -> u64 {
        return LuaPage::get_size(4 as u8);
    }

    fn get_le_deserializer() -> dyn bincode::Options <Endian = bincode::LE, Limit = bincode::NoLimit, IntEncoding = bincode::VarInt, Trailing = bincode::AllowTrailing> {
        return Options::new()
            .with_endian(bincode::config::LittleEndian);
    }

    fn get_be_deserializer() -> dyn bincode::Options <Endian = bincode::BE, Limit = bincode::NoLimit, IntEncoding = bincode::VarInt, Trailing = bincode::AllowTrailing>{
        return Options::new()
            .with_endian(bincode::config::BigEndian);
    }

    fn get_x64_size() -> u64 {
        return LuaPage::get_size(8 as u8);
    }

    fn get_comment(&self, vaddr: &u64, vaddr_base: &u64, paddr: &u64, paddr_base: &u64) -> Comment {
        return Comment {
            search: "lua_page",
            paddr,
            vaddr,
            paddr_base,
            vaddr_base,
            prev: self.get_prev(),
            next: self.get_next(),
            gcolistprev: self.get_gcolistprev(),
            gcolistnext: self.get_gcolistnext(),
            freelist: self.get_free_list(),

            block_size: self.get_block_size(),
            page_size: self.get_page_size(),
            free_next: self.get_free_next(),
            busy_blocks: self.get_busy_blocks(),
        };
    }

    fn is_valid_header(&self, di: &DataInterface, o_max_block_size : Option<u32>, o_page_size:Option<u32>) -> bool {

        let basic_constraints = di.vmem_info.ptr_lookup.contains_key(&self.get_prev()) &&
            di.vmem_info.ptr_lookup.contains_key(&self.get_next()) &&
            di.vmem_info.ptr_lookup.contains_key(&self.get_gcolistprev()) &&
            di.vmem_info.ptr_lookup.contains_key(&self.get_gcolistnext()) &&
            self.busy_blocks >= 0;

        let block_size_check = match o_max_block_size {
            Some(bsz) => self.get_block_size() <= bsz,
            None => true,
        };

        let page_size_check = match o_page_size {
            Some(psz) => self.get_page_size() == psz,
            None => true,
        };

        return basic_constraints && block_size_check && page_size_check;
    }
}


#[repr(C)]
#[derive(Debug, Deserialize)]
struct LuaPageX32 {
    pub prev: u32,
    pub next: u32,
    pub gcolistprev: u32,
    pub gcolistnext: u32,
    pub page_size: i32,
    pub block_size: i32,
    pub free_list: u32,
    pub free_next: i32,
    pub busy_blocks: i32,
}

impl LuaPage for LuaPageX32 {

    fn load(buffer: &[u8], data_interface: Box<DataInterface>) -> Result<Self, dyn StdErr> {
        if buffer.len() < LuaPage::get_x32_size() {
            return Err();
        }

        // #FIXME #TODO implement architecture specific deserialization
        match &data_interface.vmem_info.endian {
            ENDIAN::BIG => {
                let page = Options::new()
                                       .with_endian(bincode::config::BigEndian)

                                       .deserialize(&buffer)?;
                return Ok(page);
            },
            ENDIAN::LITTLE => {
                let page = LuaPage::get_le_deserializer().deserialize(&buffer)?;
                return Ok(page);
            },
        }
    }

    fn get_prev(&self) -> u64 {
        return self.prev as u64;
    }
    fn get_next(&self) -> u64 {
        return self.next as u64;
    }
    fn get_gcolistprev(&self) -> u64 {
        return self.gcolistprev as u64;
    }
    fn get_gcolistnext(&self) -> u64 {
        return self.gcolistnext as u64;
    }
    fn get_page_size(&self) -> i32 {
        return self.page_size as i32;
    }
    fn get_block_size(&self) -> i32 {
        return self.block_size as i32;
    }
    fn get_free_list(&self) -> u64 {
        return self.free_list as u64;
    }
    fn get_free_next(&self) -> i32 {
        return self.free_next;
    }
    fn get_busy_blocks(&self) -> i32 {
        return self.busy_blocks;
    }
}

#[repr(C)]
#[derive(Debug, Deserialize)]
struct LuaPageX64 {
    pub prev: u64,
    pub next: u64,
    pub gcolistprev: u64,
    pub gcolistnext: u64,
    pub page_size: i32,
    pub block_size: i32,
    pub free_list: u64,
    pub free_next: u32,
    pub busy_blocks: u32,
}

impl LuaPage for LuaPageX64 {
    fn load(buffer: &[u8], data_interface: Box<DataInterface>) -> Result<Self, dyn StdErr> {
        if buffer.len() < LuaPage::get_x32_size() {
            return Err();
        }

        // #FIXME #TODO implement architecture specific deserialization
        match &data_interface.vmem_info.endian {
            ENDIAN::BIG => {
                let page = LuaPage::get_be_deserializer().deserialize(&buffer)?;
                return Ok(page);
            },
            ENDIAN::LITTLE => {
                let page = LuaPage::get_le_deserializer().deserialize(&buffer)?;
                return Ok(page);
            },
        }
    }

    fn get_prev(&self) -> u64 {
        return self.prev as u64;
    }
    fn get_next(&self) -> u64 {
        return self.next as u64;
    }
    fn get_gcolistprev(&self) -> u64 {
        return self.gcolistprev as u64;
    }
    fn get_gcolistnext(&self) -> u64 {
        return self.gcolistnext as u64;
    }
    fn get_page_size(&self) -> i32 {
        return self.page_size as i32;
    }
    fn get_block_size(&self) -> i32 {
        return self.block_size as i32;
    }
    fn get_free_list(&self) -> u64 {
        return self.free_list as u64;
    }
    fn get_free_next(&self) -> i32 {
        return self.free_next;
    }
    fn get_busy_blocks(&self) -> i32 {
        return self.busy_blocks;
    }
}


#[derive(Debug, Clone)]
pub struct LuaPageSearch {
    pub addr_to_lp: Box<HashMap<u64, dyn LuaPage>>,
    pub start: Option<u64>,
    pub stop: Option<u64>,
    pub data_interface: Box<DataInterface>,
    pub comments: Box<BTreeMap<u64, Box<Comment>>>,
    pub page_size: Option<u32>,
    pub max_block_size : Option<u32>
}

impl LuaPageSearch {
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


        while pos + incr - 1 < vaddr_buf.len() as u64 {
            let vaddr = pos + virt_base;
            let paddr = pos + phys_base;
            // debug!("Reading buffer at {:08x}", pos );
            let o_lp = LuaPage::load(&vaddr_buf[pos as usize ..], &self.data_interface);
            if o_lp.is_none() {
                pos += incr;
                continue;
            }

            let lp = o_lp.unwrap();
            if ! lp.is_valid_header(&self.data_interface, self.max_block_size, self.page_size) {
                pos += incr;
                continue;
            }

            let i_comment = lp.get_comment(vaddr, paddr, virt_base, phys_base);
            let comment = Box::new(i_comment);
            self.comments.insert(vaddr, comment.clone());

            let mut sr = SearchResult::default();
            sr.boundary_offset = paddr as u64;
            sr.size = incr;

            sr.vaddr = vaddr;
            sr.paddr = paddr;
            sr.section_name = match di.get_vaddr_section_name(vaddr) {
                Some(s) => s.clone(),
                None => "".to_string(),
            };
            sr.digest = "".to_string();
            let result = Box::new(sr);
            search_results.push(result);

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
        let vaddr_base = self.data_interface.get_vaddr_base_from_vaddr(&virt_base).unwrap();
        let paddr_base = self.data_interface.get_paddr_base_from_vaddr(&virt_base).unwrap();
        let end: u64 = buffer.len() as u64;
        while pos < end {
            let vaddr = pos + virt_base;
            let paddr = pos + phys_base;
            // debug!("Reading buffer at {:08x}", pos );
            let o_lp = LuaPage::load(&buffer[pos as usize ..], &self.data_interface);
            if o_lp.is_none() {
                pos += incr;
                continue;
            }

            let lp = o_lp.unwrap();
            if ! lp.is_valid_header(&self.data_interface, self.max_block_size, self.page_size) {
                pos += incr;
                continue;
            }

            let i_comment = lp.get_comment(vaddr, paddr, vaddr_base, paddr_base);
            let comment = Box::new(i_comment);
            self.comments.insert(vaddr, comment.clone());

            let mut sr = SearchResult::default();
            sr.boundary_offset = paddr as u64;
            sr.size = incr;

            sr.vaddr = vaddr;
            sr.paddr = paddr;
            sr.section_name = match self.data_interface.get_vaddr_section_name(vaddr) {
                Some(s) => s.clone(),
                None => "".to_string(),
            };
            sr.digest = "".to_string();
            let result = Box::new(sr);
            search_results.push(result);

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

    pub fn new(start: Option<u64>, stop: Option<u64>, data_interface: Box<DataInterface>, max_block_size: Option<u32>, page_size: Option<u32>) -> Self {
        LuaPageSearch {
            start: start.clone(),
            stop: stop.clone(),
            addr_to_lp: Box::new(HashMap::new()),
            data_interface: data_interface,
            comments: Box::new(BTreeMap::new()),
            max_block_size: max_block_size,
            page_size: page_size
        }
    }

    pub fn get_comments(&self) -> Vec<Box<Comment>> {
        let mut comments = Vec::new();
        for (_, c) in self.comments.iter() {
            comments.push(c.clone())
        }
        return comments;
    }
}
