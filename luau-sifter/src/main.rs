use std::collections::HashMap;


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

// use log4rs::append::console::ConsoleAppender;
// use log4rs::config::{Appender, Root};
// use log4rs::Config;
use log::{debug, error, info};
use log4rs;
use mem_analysis::memory::{MemRange, MemRanges};
use mem_analysis::radare::{RadareMemoryInfo, RadareMemoryInfos};
use mem_analysis::buffer::{DataBuffer};

// #[derive(Debug, Default)]
// pub struct LookupTables<'a>{
//     vaddr_table: HashMap<u64, RadareMemoryInfo>,
//     vaddr_to_paddr: HashMap<u64, u64>,
//     data: &'a [u8],
// }



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

    #[arg(short, long, value_name = "FILE")]
    log_conf: Option<PathBuf>,


}

pub struct DataInterface {
    pub buffer : DataBuffer,
    pub ranges : MemRanges,
}



// fn open_file(fname: String ) -> Result<File, Err> {
//     let pb = File::open(fname)?;
//     return Ok(pb);
// }

fn interactive_loop() -> () {

}


fn main() {
    let mut open_files: HashMap<String, File> = HashMap::new();
    let args = Arguments::parse();



    let log_conf = match args.log_conf {
        Some(path) => {path},
        None => {PathBuf::from("../logging_config.yaml")}
    };
    // println!("log file = {}", log_conf);

    log4rs::init_file(log_conf, Default::default()).unwrap();

    debug!("Loading radare info from: {:#?}.", args.r2_sections.as_os_str());
    let infos = RadareMemoryInfos::from_radare_json(&args.r2_sections);
    // let mem_info = infos.items.get(0).unwrap();

    debug!("Creating MemRanges and Loading dump file into memory: {:#?}.", args.dmp.as_os_str());
    let datainterface = DataInterface{
        buffer: DataBuffer::from_pathbuf(&args.dmp, true),
        ranges: MemRanges::from_radare_infos(&infos)
    };
    // {
    //     virt_base_address: 0,
    //     phys_base_address: 0,
    //     size: 0,
    //     section_name: "".to_string(),
    //     flags: "".to_string(),
    //     data: vec![],
    // });
    println!("{}", infos.items.get(0).unwrap());

    // for info in infos.items.iter() {
    //     println!("{}", info);
    // }

    if args.interactive {
        interactive_loop();
    }
    println!("Enter the command");
}
