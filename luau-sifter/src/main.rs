use std::error::{Error as StdErr};
use std::path::{PathBuf};
use clap::Parser;
use log::{debug};

use mem_analysis::memory::{MemRanges};
use mem_analysis::radare::{RadareMemoryInfos};
use mem_analysis::buffer::{DataBuffer};


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

fn interactive_loop() -> Result<(), Box<dyn StdErr>> {
    println!("Enter the command");
    Ok(())
}


fn main() -> Result<(), Box<dyn StdErr>>{
    let args = Arguments::parse();



    let log_conf = match args.log_conf {
        Some(path) => {path},
        None => {PathBuf::from("../logging_config.yaml")}
    };
    log4rs::init_file(log_conf, Default::default()).unwrap();

    debug!("Loading radare info from: {:#?}.", args.r2_sections.as_os_str());
    let infos = RadareMemoryInfos::from_radare_json(&args.r2_sections);

    debug!("Creating MemRanges and Loading dump file into memory: {:#?}.", args.dmp.as_os_str());
    let _datainterface = DataInterface{
        buffer: DataBuffer::from_pathbuf(&args.dmp, true),
        ranges: MemRanges::from_radare_infos(&infos)
    };
    println!("{}", infos.items.get(0).unwrap());

    if args.interactive {
        return interactive_loop();
    }

    Ok(())
}
