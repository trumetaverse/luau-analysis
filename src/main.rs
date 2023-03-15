use std::collections::HashMap;
use LuaObjectExtractor::memory::*;

use md5;
use regex::bytes::Regex;
use std::fmt::{Display, Formatter, Result as FmtResult};
// use regex::bytes::{Regex, Matches};
// use std::io::{BufReader, Error as BufError, SeekFrom, Seek, BufRead, Read, Write};
use std::io::{Read, Write};
// use base64::{Engine as _, engine::general_purpose};
use std::fs::{create_dir_all, File, OpenOptions}; //, Metadata};

// use std::path::Component::ParentDir;
use std::path::{Path, PathBuf};

use clap::Parser;
use serde;
use serde::Deserialize;








#[derive(Debug, Deserialize)]
pub struct RadareMemoryInfo {
    name: String,
    size: u64,
    vsize: u64,
    perm: String,
    paddr: u64,
    vaddr: u64,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct RadareMemoryInfos {
    pub items: Vec<RadareMemoryInfo>,
}

impl Display for RadareMemoryInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{} perms={} paddr={:08x} size={:08x} vaddr={:08x} vsize={:08x}",
            self.name, self.perm, self.paddr, self.size, self.vsize, self.vaddr
        )
    }
}


let PAGE_MASK = 
#[derive(Debug, Default)]
pub struct LookupTables<'a>{
    vaddr_table: HashMap<u64, RadareMemoryInfo>,
    vaddr_to_paddr: HashMap<u64, u64>,
    data: &'a [u8],
}


// use log4rs::append::console::ConsoleAppender;
// use log4rs::config::{Appender, Root};
// use log4rs::Config;
use log::{debug, error, info};
use log4rs;
use LuaObjectExtractor::memory::MemorySection;

static ROBLOX_REGEX_START: &str = r"(:?<roblox)";
static ROBLOX_REGEX_END: &str = r"(:?</roblox>)";

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// input path of the memory dump
    #[arg(short, long, action, value_name = "FLAG")]
    interactive: bool,

    /// input path of the memory dump
    #[arg(short, long, value_name = "FILE")]
    dmp: PathBuf,

    /// input
    #[arg(short, long, value_name = "FILE")]
    r2_sections: PathBuf,

    /// regular expression for start
    #[arg(short = 's', long, value_name = "STRING")]
    regex_start: Option<String>,

    /// regular expression for end
    #[arg(short = 'e', long, value_name = "FILE")]
    regex_end: Option<String>,
}

fn parse_radare_name(info: &String) -> RadareMemoryInfo {
    let name_split_vector: Vec<&str> = info.split(" ").collect::<Vec<&str>>();
    let mut paddr: u64 = 0;
    let mut stype: u64 = 0;
    let mut alloc: u64 = 0;
    let mut state: u64 = 0;
    for vstr in name_split_vector.iter() {
        if vstr.starts_with("paddr") {
            let imm = *vstr.split("=").collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            paddr = v.unwrap();
        } else if vstr.starts_with("state") {
            let imm = *vstr.split("=").collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            state = v.unwrap();
        } else if vstr.starts_with("allocation") {
            let imm = *vstr.split("=").collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            alloc = v.unwrap();
        } else if vstr.starts_with("type") {
            let imm = *vstr.split("=").collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            stype = v.unwrap();
        }
    }
    let name = *name_split_vector.get(name_split_vector.len() - 1).unwrap();
    return RadareMemoryInfo {
        name: name.to_string(),
        // size: info.size,
        size: 0,
        vsize: 0,
        // vaddr: info.address,
        paddr: paddr,
        // stype: stype,
        // state: state,
        // alloc_protection: alloc,
        // flags: info.flags.clone(),
        perm: "".to_string(),
        vaddr: 0,
    };
}

// fn open_file(fname: String ) -> Result<File, Err> {
//     let pb = File::open(fname)?;
//     return Ok(pb);
// }

fn main() {
    let mut open_files: HashMap<String, File> = HashMap::new();

    log4rs::init_file("logging_config.yaml", Default::default()).unwrap();
    let args = Arguments::parse();
    let mut memorySections: Vec<MemorySection> = Vec::new();
    let infos: RadareMemoryInfos = {
        let text = std::fs::read_to_string(&args.r2_sections).unwrap();
        serde_json::from_str::<RadareMemoryInfos>(&text).unwrap()
        // let mut rmis : RadareMemoryInfos = RadareMemoryInfos{ infos: vec![]};
        // for val in foos.infos.iter() {
        //     let rmi = parse_radare_name(val);
        //     rmis.infos.push(rmi);
        // }
        // rmis
    };
    memorySections.push(MemorySection {
        virt_base_address: 0,
        phys_base_address: 0,
        size: 0,
        section_name: "".to_string(),
        flags: "".to_string(),
        data: vec![],
    });
    println!("{}", infos.items.get(0).unwrap());

    for info in infos.items.iter() {
        println!("{}", info);
    }
    println!("Enter the command");
}
