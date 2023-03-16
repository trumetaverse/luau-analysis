use rangemap::RangeMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::collections::HashMap;
use std::io::{Read, Write};
// use base64::{Engine as _, engine::general_purpose};
use std::fs::{create_dir_all, File, OpenOptions}; //, Metadata};

// use std::path::Component::ParentDir;
use std::path::{Path, PathBuf};
use log::{debug, error, info};

// use radare::{RadareMemoryInfo, RadareMemoryInfos};

// pub struct SourceMeta<'a>{
//     source_name: &'a str,
//     source_type: &'a str,
// }

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DataBuffer {
    pub filename : Option<String>,
    pub size : u64,
    pub data : Option<Vec<u8>>,
    // pub vaddr_to_paddr_start : RangeMap<u64, u64>,
    // pub paddr_to_vaddr_start : RangeMap<u64, u64>,
}

impl DataBuffer {
    pub fn load_data(&mut self) -> (){

        if self.filename.is_none() {
            error!("No filename provided for the backend data buffer.");
            return ();
        }
        let r_file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.filename.as_ref().unwrap());

        debug!("Loading data buffer from file: {}.", self.filename.as_ref().unwrap());
        assert_eq!(true, r_file.is_ok());
        let mut file = r_file.unwrap();
        self.size = file.metadata().unwrap().len();
        let mut data = Vec::with_capacity(self.size as usize);
        let read_bytes = file.read_to_end(&mut data);
        assert_eq!(true, read_bytes.is_ok());
        assert_eq!(true, *read_bytes.as_ref().unwrap() >= 0);
        debug!("Load {} bytes from from file: {}.", read_bytes.unwrap(), self.filename.as_ref().unwrap());
        self.data = Some(data);
    }

    pub fn from_pathbuf(ifilename : &PathBuf, load_data : bool) -> Self {
        debug!("Creating a data buffer from path: {}.", ifilename.as_os_str().to_str().unwrap());
        let mut db = DataBuffer {
            filename: Some(ifilename.as_os_str().to_str().expect("REASON").to_string()),
            size: 0,
            // vaddr_to_paddr_start: RangeMap::new(),
            // paddr_to_vaddr_start: RangeMap::new(),
            data: None,
        };

        if load_data && db.filename.is_some() {
            db.load_data();
        }
        return db;
    }
    pub fn load_data_slice(&self, buffer : &[u8]) -> (){}
    pub fn load_data_vec(&self, buffer : &Vec<u8>) -> (){}
    pub fn load_data_path(&self, path: &PathBuf) -> (){}
    pub fn load_data_file(&self, path: &File) -> (){}

    pub fn add_vaddr_mapping(&mut self, vaddr: u64, paddr: u64, size: u64) -> () {
        // self.vaddr_to_paddr_start.insert(vaddr .. vaddr + size, paddr);
        // self.paddr_to_vaddr_start.insert(paddr .. paddr + size, vaddr);
    }

}