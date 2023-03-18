use clap::Parser;
use log::{debug, info, error};
use std::error::Error as StdErr;
use std::path::{Path, PathBuf};
use std::fs::{create_dir_all};

use regex::bytes::Regex;
use regex::RegexBuilder;
use serde_json::json;
use md5;

use mem_analysis::buffer::DataBuffer;
use mem_analysis::memory::MemRanges;
use mem_analysis::radare::RadareMemoryInfos;
use luau_search::regex::{RegexSearch, ROBLOX_REGEX_START, ROBLOX_REGEX_END};
use luau_search::search::{Search, SearchResult};
use luau_search::pointer::{PointerSearch, RangePointer};

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    /// input path of the memory dump
    #[arg(short, long, action, value_name = "FLAG")]
    interactive: bool,

    /// input path of the memory dump
    #[arg(short, long, action, value_name = "FLAG")]
    quick_test: bool,

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
    #[arg(short = 'e', long, value_name = "String")]
    regex_end: Option<String>,

    #[arg(short, long, value_name = "FILE")]
    log_conf: Option<PathBuf>,

    /// input path of the memory dump
    #[arg(short, long, value_name = "FILE")]
    output_path: Option<PathBuf>,
}

pub struct DataInterface {
    pub buffer: DataBuffer,
    pub ranges: MemRanges,
}

fn check_create(ofilename: &PathBuf) -> std::io::Result<()> {
    if Path::new(ofilename).exists() && Path::new(ofilename).is_dir() {
        return Ok(());
    }
    return create_dir_all(ofilename);
}

fn compute_buffer_digest(data: &[u8]) -> String {
    return format!("{:x}", md5::compute(data));
}

fn search_regex_all(spattern : String, epattern : String, data_interface : &DataInterface) -> Vec<SearchResult> {
    debug!(
        "Searching Raw Data Buffer for {} => {}.", spattern, epattern,
    );
    let mut search_results = Vec::new();
    let o_ro_buf = data_interface.buffer.get_shared_buffer();
    if !o_ro_buf.is_some() {
        error!("No data loaded, can't search.");
        return search_results;
    }
    let ro_buf = o_ro_buf.unwrap();

    let search = RegexSearch::new(&spattern, &epattern, None, None,
                                  None, Some(0), Some(0));
    let r_results = search.search_buffer(&ro_buf);

    if r_results.is_ok() {
        let mut results = r_results.unwrap();
        search_results.append(&mut results);
        info!(
                "Found {} results in over entire dump.",
                results.len()
            );
    }

    // update the addressing in the results
    for (_k, mr) in data_interface.ranges.pmem_ranges.iter() {
        for r in search_results.iter_mut() {

            let va = &mr.vaddr_start;
            let pa = &mr.paddr_start;
            let ps = &mr.size;
            let file_offset = r.boundary_offset;
            if *pa <= file_offset && file_offset <= *pa + *ps {
                r.vaddr = *va + (file_offset - *pa);
                r.section_name = mr.name.clone();
                debug!(
            "Updating resulting with Memory Range: {} base virtual address.  file offset ({:08x}) falls between {:08x} and {:08x}.",
                mr.name, file_offset, *pa, *pa+*ps);

            }
        }
    }
    // update buffer digests
    for r in search_results.iter_mut() {
        let start = *(&r.paddr);
        let end = *(&r.paddr) + *(&r.size);
        let data = &ro_buf[start as usize .. end as usize];
        r.digest = compute_buffer_digest(data);
    }
    debug!("Found {} results.", search_results.len());
    // for r in search_results.iter() {
    //     println!("{:#?}", r);
    // }
    println!("{}", json!(search_results));

    return search_results;

}

fn search_regex_ranges(spattern : String, epattern : String, data_interface : &DataInterface) -> Vec<SearchResult> {
    // let search = RegexSearch::new(&spattern, &epattern, None, None, None, Some(0), Some(0));
    debug!(
        "Searching Memory Ranges for {} => {}.", spattern, epattern,
    );
    let o_ro_buf = data_interface.buffer.get_shared_buffer();
    let mut search_results = Vec::new();
    if !o_ro_buf.is_some() {
        error!("No data loaded, can't search.");
        return search_results;
    }
    let ro_buf = o_ro_buf.unwrap();


    let memory_regex = RegexBuilder::new("Memory_section")
        .case_insensitive(true)
        .build()
        .expect("Invalid Regex");

    for (_k, mr) in data_interface.ranges.pmem_ranges.iter() {
        // if !memory_regex.is_match(&mr.name) {
        //     // info!("Skipping {} since it's not heap allocated.",mr.name);
        //     continue;
        // }
        debug!(
            "Searching Memory Range: {} of {} bytes from starting at vaddr {:08x} and paddr {:08x}.",
            mr.name, mr.vsize, mr.vaddr_start, mr.paddr_start
        );
        let vaddr:u64 = mr.vaddr_start;
        let paddr:u64 = mr.paddr_start;
        let size:u64 = mr.size;
        let sbuff:&[u8] = &ro_buf[paddr as usize .. (paddr + size) as usize];
        let search = RegexSearch::new(&spattern, &epattern, None, None,
                                      None, Some(vaddr), Some(paddr));
        let r_results = search.search_buffer(sbuff);

        if r_results.is_ok() {
            let mut results = r_results.unwrap();
            for r in results.iter_mut() {
                r.section_name = mr.name.clone();
                let start = *(&r.paddr);
                let end = *(&r.paddr) + *(&r.size);
                let data = &ro_buf[start as usize .. end as usize];
                r.digest = compute_buffer_digest(data);
            }

            search_results.append(&mut results);
            info!(
                "Found {} results in {}.",
                results.len(), mr.name
            );

        } else {
            info!(
                "Found no results in {}.",mr.name
            );
        }
    }
    info!("Found {} results.", search_results.len());
    // for r in search_results.iter() {
    //     println!("{:#?}", r);
    // }
    println!("{}", json!(search_results));
    return search_results;
}

fn write_search_results(output_filename : PathBuf, search_results : &Vec<SearchResult>) -> () {
    let wres = std::fs::write(
        &output_filename,
        serde_json::to_string_pretty(&search_results).unwrap(),
    );
    match wres {
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
    }
}


fn interactive_loop(spattern: String, epattern: String, o_outputdir : Option<PathBuf>, data_interface: & DataInterface) -> Result<(), Box<dyn StdErr>> {
    println!("Enter the command");
    debug!(
        "Executing the regex search with: {} ==> {}.",
        spattern, epattern
    );

    let full_dump_results = search_regex_all(spattern.clone(), epattern.clone(),&data_interface);
    let range_results = search_regex_ranges(spattern.clone(), epattern.clone(),&data_interface);

    if o_outputdir.is_some() {
        let ofilepath = o_outputdir.as_ref().unwrap();
        info!("Checking for output directory: {}", ofilepath.display());
        match check_create(&ofilepath) {
            Ok(_) => {}
            Err(e) => {
                let msg = format!(
                    "Failed to create output directory: {}. {}",
                    ofilepath.display(),
                    e
                );
                error!("{}", msg);
                panic!("{}", msg);
            }
        };
        let fd_results_filename = ofilepath.join("full_dump_roblox_assets.json");
        write_search_results(fd_results_filename,&full_dump_results);
        let mr_results_filename = ofilepath.join("memory_ranges_roblox_assets.json");
        write_search_results(mr_results_filename,&range_results);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn StdErr>> {
    let args = Arguments::parse();

    if args.quick_test {
        let mut ptr_search = PointerSearch::new();
    }

    let regex_start: Regex = match args.regex_start {
        Some(pattern) => match Regex::new(pattern.as_str()) {
            Ok(r) => r,
            Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
        },
        None => Regex::new(ROBLOX_REGEX_START).unwrap(),
    };

    let regex_end: Regex = match args.regex_end {
        Some(pattern) => match Regex::new(pattern.as_str()) {
            Ok(r) => r,
            Err(e) => panic!("Invalid regular expression provided: '{}', {}", pattern, e),
        },
        None => Regex::new(ROBLOX_REGEX_END).unwrap(),
    };

    let log_conf = match args.log_conf {
        Some(path) => path,
        None => PathBuf::from("../logging_config.yaml"),
    };
    log4rs::init_file(log_conf, Default::default()).unwrap();

    debug!(
        "Loading radare info from: {:#?}.",
        args.r2_sections.as_os_str()
    );
    let infos = RadareMemoryInfos::from_radare_json(&args.r2_sections);

    debug!(
        "Creating MemRanges and Loading dump file into memory: {:#?}.",
        args.dmp.as_os_str()
    );
    let data_interface = DataInterface {
        buffer: DataBuffer::from_pathbuf(&args.dmp, true),
        ranges: MemRanges::from_radare_infos(&infos),
    };
    println!("{}", infos.items.get(0).unwrap());

    if args.interactive {
        return interactive_loop(regex_start.to_string(), regex_end.to_string(), args.output_path, &data_interface);
    }

    Ok(())
}
