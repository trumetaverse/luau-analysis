use crate::search::*;
use std::error::Error as StdErr;
use std::sync::{Arc, RwLock};

use log::{debug, error, info};
use md5;
use regex::bytes::Regex;

use mem_analysis::data_interface::DataInterface;

pub static ROBLOX_REGEX_START: &str = r"(:?<roblox)";
pub static ROBLOX_REGEX_END: &str = r"(:?</roblox>)";

#[derive(Debug, PartialEq, Clone)]
pub struct Comment {
    pub search: String,
    pub start_pattern: String,
    pub end_pattern: String,
    pub vaddr: u64,
    pub paddr: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RegexBlockSearch {
    pub start_pattern: String,
    pub end_pattern: String,
    pub start: Option<u64>,
    pub stop: Option<u64>,
    pub offset_type: Option<OffsetType>,
    pub base_vaddr: Option<u64>,
    pub base_paddr: Option<u64>,
    pub comments: Vec<Comment>
}

impl Search for RegexBlockSearch {
    fn search_buffer_next(
        &mut self,
        buffer: &[u8],
        pos: u64,
    ) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        return self.perform_search_buffer_next(buffer, pos);
    }
    fn search_buffer(&mut self, buffer: &[u8]) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        return self.perform_search_buffer(buffer);
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
        di_arw: Arc<RwLock<Box<DataInterface>>>,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let di = di_arw.read().unwrap();
        let o_ro_buf = di.buffer.get_shared_buffer();
        let search_results = Vec::new();
        if !o_ro_buf.is_some() {
            error!("No data loaded, can't search.");
            return Ok(search_results);
        }
        let ro_buf = o_ro_buf.unwrap();
        // TODO pass the DataInterface to the struct and use that to interact with the backend data
        return self.perform_search_buffer(ro_buf);
    }
    fn search_interface_with_bases(
        &mut self,
        di_arw: Arc<RwLock<Box<DataInterface>>>,
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let di = di_arw.read().unwrap();
        let o_ro_buf = di.buffer.get_shared_buffer();
        let search_results = Vec::new();
        if !o_ro_buf.is_some() {
            error!("No data loaded, can't search.");
            return Ok(search_results);
        }
        let ro_buf = o_ro_buf.unwrap();
        // TODO pass the DataInterface to the struct and use that to interact with the backend data
        return self.perform_search_buffer_with_bases(ro_buf, phys_base, virt_base);
    }
}
impl RegexBlockSearch {
    fn compute_buffer_digest(&self, data: &[u8]) -> String {
        return format!("{:x}", md5::compute(data));
    }

    pub fn new(
        re_start_tag: &String,
        re_end_tag: &String,
        start: Option<u64>,
        stop: Option<u64>,
        offtype: Option<OffsetType>,
        base_vaddr: Option<u64>,
        base_paddr: Option<u64>,
    ) -> Self {
        let regex_start: Regex = match Regex::new(re_start_tag.as_str()) {
            Ok(r) => r,
            Err(e) => panic!(
                "Invalid regular expression provided: '{}', {}",
                re_start_tag, e
            ),
        };

        let regex_end: Regex = match Regex::new(re_end_tag.as_str()) {
            Ok(r) => r,
            Err(e) => panic!(
                "Invalid regular expression provided: '{}', {}",
                re_start_tag, e
            ),
        };

        RegexBlockSearch {
            stop,
            start,
            start_pattern: regex_start.to_string(),
            end_pattern: regex_end.to_string(),
            offset_type: offtype,
            base_vaddr: base_vaddr,
            base_paddr: base_paddr,
            comments: Vec::new(),
        }
    }

    pub fn create(
        re_start_tag: &Option<String>,
        re_end_tag: &Option<String>,
        start: Option<u64>,
        stop: Option<u64>,
        offtype: Option<OffsetType>,
        base_vaddr: Option<u64>,
        base_paddr: Option<u64>,
    ) -> Self {
        let regex_start: Regex = match re_start_tag {
            Some(pattern) => match Regex::new(pattern.as_str()) {
                Ok(r) => r,
                Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
            },
            None => Regex::new(ROBLOX_REGEX_START).unwrap(),
        };

        let regex_end: Regex = match re_end_tag {
            Some(pattern) => match Regex::new(pattern.as_str()) {
                Ok(r) => r,
                Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
            },
            None => Regex::new(ROBLOX_REGEX_END).unwrap(),
        };
        return RegexBlockSearch::new(
            &regex_start.to_string(),
            &regex_end.to_string(),
            stop,
            start,
            offtype,
            base_vaddr,
            base_paddr,
        );
    }

    fn find_next_pattern(&self, buffer: &[u8], pattern: &Regex) -> Option<Vec<usize>> {
        let m = pattern.find(buffer);
        let results = match m {
            Some(_match) => {
                let mut v = Vec::new();
                v.push(_match.start());
                v.push(_match.end());
                Some(v)
            }
            None => None,
        };
        return results;
    }

    fn perform_search_buffer_next(
        &mut self,
        buffer: &[u8],
        pos: u64,
    ) -> Result<Option<SearchResult>, Box<dyn StdErr>> {
        let start_pattern = Regex::new(&self.start_pattern.as_str()).unwrap();
        let end_pattern = Regex::new(&self.end_pattern.as_str()).unwrap();

        let mut search_result = Ok(None);
        let start_seq: Option<Vec<usize>> =
            self.find_next_pattern(&buffer[pos as usize..], &start_pattern);
        if start_seq.is_none() {
            info!(
                "Unable to identify a start marker after pos ({:08x}) in buffer.",
                pos
            );
            return search_result;
        }

        let start_end = start_seq.as_ref().unwrap().get(1).unwrap();
        let end_seq: Option<Vec<usize>> =
            self.find_next_pattern(&buffer[pos as usize + start_end..], &end_pattern);
        if end_seq.is_none() {
            info!(
                "Unable to identify a end marker after pos ({:08x}) in buffer.",
                pos as usize + start_end
            );
            return search_result;
        }
        let start = start_seq.as_ref().unwrap().get(0).unwrap() + pos as usize;
        let end = end_seq.as_ref().unwrap().get(1).unwrap() + start_end + pos as usize;
        info!(
            "Found a suitable buffer from: {:08x} ==> {:08x}.",
            pos as usize + start,
            pos as usize + end
        );

        let vaddr = match &self.base_vaddr {
            Some(v) => *v + start as u64,
            None => start as u64,
        };

        let paddr = match &self.base_paddr {
            Some(v) => *v + start as u64,
            None => start as u64,
        };
        let comment = Comment{search: "regexblock".to_string(),
            start_pattern: self.start_pattern.to_string(),
            end_pattern: self.end_pattern.to_string(),
            vaddr: vaddr,
            paddr: paddr};

        self.comments.push(comment);
        // let mut rdata: Vec<u8> = Vec::with_capacity(end - start);
        // rdata.copy_from_slice(&buffer[start..end]);
        let mut sr = SearchResult {
            boundary_offset: start as u64,
            size: end as u64 - start as u64,
            // data: rdata,
            start_pattern: self.start_pattern.to_string(),
            end_pattern: self.end_pattern.to_string(),
            vaddr: vaddr,
            paddr: paddr,
            section_name: "".to_string(),
            digest: self.compute_buffer_digest(&buffer[start..end]).clone(),
            comment: "".to_string(),
            data: None,
        };
        sr.comment = format!(
            "regexblock| vstart:{:08x} pstart:{:08x} size:{:08x}",
            sr.vaddr, sr.paddr, sr.size
        );

        search_result = Ok(Some(sr));
        return search_result;
    }

    pub fn perform_search_buffer_with_bases(
        &mut self,
        buffer: &[u8],
        phys_base: u64,
        virt_base: u64,
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let mut search_results = self.perform_search_buffer(buffer)?;
        for r in search_results.iter_mut() {
            let va = virt_base + r.boundary_offset;
            let pa = phys_base + r.boundary_offset;
            r.vaddr = va;
            r.paddr = pa;
            r.comment = format!(
                "regexblock| vstart:{:08x} pstart:{:08x} size:{:08x}",
                r.vaddr, r.paddr, r.size
            );
        }
        return Ok(search_results);
    }

    fn perform_search_buffer(
        &mut self,
        buffer: &[u8],
    ) -> Result<Vec<Box<SearchResult>>, Box<dyn StdErr>> {
        let start_pattern = Regex::new(&self.start_pattern.as_str()).unwrap();
        let end_pattern = Regex::new(&self.end_pattern.as_str()).unwrap();

        let stop: u64 = match &self.stop {
            Some(x) => *x,
            None => buffer.len() as u64,
        };
        let mut search_results = Vec::new();

        let mut pos: u64 = match &self.start {
            Some(x) => *x,
            None => 0,
        };
        info!("Searching for blocks of data.");
        loop {
            debug!(
                "Searching from pos ({:08x}) => ({:08x}) in the content buffer.",
                pos,
                buffer.len()
            );
            let start_seq: Option<Vec<usize>> =
                self.find_next_pattern(&buffer[pos as usize..], &start_pattern);
            if start_seq.is_none() {
                info!(
                    "Unable to identify a start marker after pos ({:08x}) in buffer.",
                    pos
                );
                break;
            }
            let start_end = start_seq.as_ref().unwrap().get(1).unwrap();
            let end_seq: Option<Vec<usize>> =
                self.find_next_pattern(&buffer[pos as usize + start_end..], &end_pattern);
            if end_seq.is_none() {
                info!(
                    "Unable to identify a end marker after pos ({:08x}) in buffer.",
                    pos as usize + start_end
                );
                break;
            }

            let start = start_seq.as_ref().unwrap().get(0).unwrap() + pos as usize;
            let end = end_seq.as_ref().unwrap().get(1).unwrap() + start_end + pos as usize;
            info!(
                "Found a suitable buffer from: {:08x} ==> {:08x}.",
                pos as usize + start,
                pos as usize + end
            );
            //let mut rdata: Vec<u8> = Vec::with_capacity(end - start);
            //rdata.copy_from_slice(&buffer[start..end]);

            let vaddr = match &self.base_vaddr {
                Some(v) => *v + start as u64,
                None => start as u64,
            };

            let paddr = match &self.base_paddr {
                Some(v) => *v + start as u64,
                None => start as u64,
            };
            let comment = Comment{    search: "regexblock".to_string(),
                start_pattern: self.start_pattern.to_string(),
                end_pattern: self.end_pattern.to_string(),
                vaddr: vaddr,
                paddr: paddr};

            self.comments.push(comment);
            let mut sr = SearchResult {
                boundary_offset: start as u64,
                size: end as u64 - start as u64,
                // data: rdata,
                start_pattern: self.start_pattern.to_string(),
                end_pattern: self.end_pattern.to_string(),
                vaddr: vaddr,
                paddr: paddr,
                section_name: "".to_string(),
                digest: self.compute_buffer_digest(&buffer[start..end]).clone(),
                comment: "".to_string(),
                data: None,
            };
            sr.comment = format!(
                "regexblock| vstart:{:08x} pstart:{:08x} size:{:08x}",
                sr.vaddr, sr.paddr, sr.size
            );
            let result = Box::new(sr);
            search_results.push(result);
            // want to find start markers that may overlap
            // e.g. [start_marker] => [start_marker'] => [start_marker"] => [end_marker]
            pos = pos + *start_end as u64;
            if pos >= stop {
                info!(
                    "Position ({:08x}) increment exceeded the content buffer size ({:08x}).",
                    pos, stop
                );
                break;
            }
        }
        return Ok(search_results);
    }
}
