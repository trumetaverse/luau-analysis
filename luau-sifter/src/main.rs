use clap::Parser;
use log::{debug, error, info};
use std::error::Error as StdErr;
use std::fs::{create_dir_all, File};
use std::path::{Path, PathBuf};
use std::io::{BufWriter, Write};

use regex::bytes::Regex;
use regex::RegexBuilder;
use serde_json::json;

use luau_search::pointer::{PointerSearch, Comment as PtrComment};
use luau_search::luapage::{LuaPageSearch, Comment as LPComment};
use luau_search::regexblock::{RegexBlockSearch, ROBLOX_REGEX_END, ROBLOX_REGEX_START};
use luau_search::search::{Search, SearchResult};
use mem_analysis::data_interface::DataInterface;
use mem_analysis::radare::RadareMemoryInfos;

// #[derive(Debug, PartialEq, Clone, Serialize)]
// struct TString {
//     tt_ : u8,
//     marked : u8,
//     memcat : u8,
//     pad : u8,
//     atom : u16,
//
//     next_TString_ptr : u32,
//     hash : u32,
//     len : u32,
//
//     data: [u8],
// }
//
//
// impl TString {
//     fn match_testring (buffer : &[u8]) -> Option<TString> {
//         return None;
//     }
//     pub fn load(mut reader: impl Read) -> Result<Self, IOErr> {
//         // Create a Speaker where all the fields are set to some sane default
//         // (typically all zeroes)
//         let mut tstring = TString::default();
//         unsafe {
//             // Get a slice which treats the `speaker` variable as a byte array
//             let buffer: &mut [u8] = std::slice::from_raw_parts_mut(
//                 speaker.as_mut_ptr().cast(),
//                 mem::size_of::<TString>(),
//             );
//
//             // Read exactly that many bytes from the reader
//             reader.read_exact(buffer)?;
//
//         }
//     }
// }

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

// pub struct DataInterface {
//     pub buffer: DataBuffer,
//     pub ranges: MemRanges,
// }

fn check_create(ofilename: &PathBuf) -> std::io::Result<()> {
    if Path::new(ofilename).exists() && Path::new(ofilename).is_dir() {
        return Ok(());
    }
    return create_dir_all(ofilename);
}

fn search_regex_all(
    spattern: String,
    epattern: String,
    data_interface: &DataInterface,
) -> Vec<SearchResult> {
    debug!(
        "Searching Raw Data Buffer for {} => {}.",
        spattern, epattern,
    );
    let mut search_results = Vec::new();
    let o_ro_buf = data_interface.buffer.get_shared_buffer();
    if !o_ro_buf.is_some() {
        error!("No data loaded, can't search.");
        return search_results;
    }
    let ro_buf = o_ro_buf.unwrap();

    let mut search =
        RegexBlockSearch::new(&spattern, &epattern, None, None, None, Some(0), Some(0));
    let r_results = search.search_buffer(&ro_buf);

    if r_results.is_ok() {
        let mut results = r_results.unwrap();
        info!("Found {} results in over entire dump.", results.len());

        for result in results.iter_mut() {
            search_results.push(*result.clone());
        }
    }

    // update the addressing in the results
    for (_k, mr) in data_interface.mem_ranges.pmem_ranges.iter() {
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
    debug!("Found {} results.", search_results.len());
    // for r in search_results.iter() {
    //     println!("{:#?}", r);
    // }
    //
    return search_results;
}

fn search_for_pointers(
    pointer_search: &mut PointerSearch,
    data_interface: &DataInterface,
) -> Vec<SearchResult> {
    // let search = RegexBlockSearch::new(&spattern, &epattern, None, None, None, Some(0), Some(0));
    debug!("Searching Memory Ranges pointer.");
    let mut search_results: Vec<SearchResult> = Vec::new();
    let r_search_results = pointer_search.search_interface(data_interface);
    match r_search_results {
        Ok(results) => {
            for result in results.iter() {
                search_results.push(*result.clone());
            }
        }
        Err(_) => {}
    }
    info!("Found {} results.", search_results.len());
    return search_results;
}

fn search_for_luapages(
    lp_search: &mut LuaPageSearch,
    data_interface: &DataInterface,
) -> Vec<SearchResult> {
    // let search = RegexBlockSearch::new(&spattern, &epattern, None, None, None, Some(0), Some(0));
    debug!("Searching Memory Ranges pointer.");
    let mut search_results: Vec<SearchResult> = Vec::new();
    let r_search_results = lp_search.search_interface(data_interface);
    match r_search_results {
        Ok(results) => {
            for result in results.iter() {
                search_results.push(*result.clone());
            }
        }
        Err(_) => {}
    }
    info!("Found {} results.", search_results.len());
    return search_results;
}

fn search_regex_ranges(
    spattern: String,
    epattern: String,
    data_interface: &DataInterface,
) -> Vec<SearchResult> {
    // let search = RegexBlockSearch::new(&spattern, &epattern, None, None, None, Some(0), Some(0));
    debug!("Searching Memory Ranges for {} => {}.", spattern, epattern,);
    let o_ro_buf = data_interface.buffer.get_shared_buffer();
    let mut search_results = Vec::new();
    if !o_ro_buf.is_some() {
        error!("No data loaded, can't search.");
        return search_results;
    }
    let ro_buf = o_ro_buf.unwrap();
    let _memory_regex = RegexBuilder::new("Memory_section")
        .case_insensitive(true)
        .build()
        .expect("Invalid Regex");

    for (_k, mr) in data_interface.mem_ranges.pmem_ranges.iter() {
        // if !memory_regex.is_match(&mr.name) {
        //     // info!("Skipping {} since it's not heap allocated.",mr.name);
        //     continue;
        // }
        debug!(
            "Searching Memory Range: {} of {} bytes from starting at vaddr {:08x} and paddr {:08x}.",
            mr.name, mr.vsize, mr.vaddr_start, mr.paddr_start
        );
        let vaddr: u64 = mr.vaddr_start;
        let paddr: u64 = mr.paddr_start;
        let size: u64 = mr.size;
        let sbuff: &[u8] = &ro_buf[paddr as usize..(paddr + size) as usize];
        let mut search = RegexBlockSearch::new(
            &spattern,
            &epattern,
            None,
            None,
            None,
            Some(vaddr),
            Some(paddr),
        );
        let r_results = search.search_buffer(sbuff);

        if r_results.is_ok() {
            match r_results {
                Ok(mut results) => {
                    info!("Found {} results in {}.", results.len(), mr.name);
                    for result in results.iter_mut() {
                        result.section_name = mr.name.clone();
                        search_results.push(*result.clone());
                    }
                }
                Err(_) => {}
            }
        } else {
            info!("Found no results in {}.", mr.name);
        }
    }
    info!("Found {} results.", search_results.len());
    // for r in search_results.iter() {
    //     println!("{:#?}", r);
    // }
    // println!("{}", json!(search_results));
    return search_results;
}

fn write_search_results(output_filename: PathBuf, search_results: &Vec<SearchResult>) -> () {
    let o_writer = File::create(&output_filename);
    let mut writer = match o_writer {
        Ok(file) => BufWriter::new(file),
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

    for result in search_results.iter() {
        match writeln!(writer, "{}", json!(result).to_string()) {
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
        writer.flush().unwrap();
    }
}

fn write_pointer_comments(output_filename: PathBuf, ptr_comments: &Vec<Box<PtrComment>>) -> () {
    let o_writer = File::create(&output_filename);
    let mut writer = match o_writer {
        Ok(file) => BufWriter::new(file),
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

    for result in ptr_comments.iter() {
        match writeln!(writer, "{}", json!(result).to_string()) {
            Ok(_) => {writer.flush().unwrap();}
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
}

fn write_luapage_comments(output_filename: PathBuf, ptr_comments: &Vec<Box<LPComment>>) -> () {
    let o_writer = File::create(&output_filename);
    let mut writer = match o_writer {
        Ok(file) => BufWriter::new(file),
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

    for result in ptr_comments.iter() {
        match writeln!(writer, "{}", json!(result).to_string()) {
            Ok(_) => {writer.flush().unwrap();}
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
}

fn interactive_loop(
    spattern: String,
    epattern: String,
    o_outputdir: Option<PathBuf>,
    data_interface: Box<DataInterface>,
) -> Result<(), Box<dyn StdErr>> {
    println!("Enter the command");
    debug!(
        "Executing the regex search with: {} ==> {}.",
        spattern, epattern
    );

    let mut ptr_search = PointerSearch::new(None, None, data_interface.clone());

    let mut lp_search = LuaPageSearch::new(None, None, data_interface.clone(), None, None);
    // let bv_mrs = data_interface.ranges.get_mem_ranges();
    // let mut wv_mrs = Vec::new();
    // let mut v_mrs = Vec::new();
    // for mr in bv_mrs.iter() {
    //     v_mrs.push(mr.clone());
    //     if mr.perm.find("w").is_some() {
    //         wv_mrs.push(mr.clone());
    //     }
    // }
    // debug!("Adding memranges to the pointer search.");
    // ptr_search.add_box_mem_ranges(&wv_mrs);



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

        let _lua_page = search_for_luapages(&mut lp_search, &data_interface);
        let lp_res_comments = lp_search.get_comments();
        let lp_comment_results_filename = ofilepath.join("luapage_comments.json");
        write_luapage_comments(lp_comment_results_filename, &lp_res_comments);

        let _pointer_results = search_for_pointers(&mut ptr_search, &data_interface);
        let res_comments = ptr_search.get_comments();
        let ptr_comment_results_filename = ofilepath.join("pointer_comments.json");
        write_pointer_comments(ptr_comment_results_filename, &res_comments);

        let full_dump_results = search_regex_all(spattern.clone(), epattern.clone(), &data_interface);
        let range_results = search_regex_ranges(spattern.clone(), epattern.clone(), &data_interface);

        let fd_results_filename = ofilepath.join("full_dump_roblox_assets.json");
        write_search_results(fd_results_filename, &full_dump_results);
        let mr_results_filename = ofilepath.join("memory_ranges_roblox_assets.json");
        write_search_results(mr_results_filename, &range_results);
        // let pr_results_filename = ofilepath.join("pointer_search_results.json");
        // write_search_results(pr_results_filename, &pointer_results);
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn StdErr>> {
    let args = Arguments::parse();

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

    if args.quick_test {
        // debug!("Performing quick test of ptr search.");
        // let mut ptr_search = PointerSearch::new(None, None, Some(32), None, None, None,  None);
        // debug!("Creating memranges for the pointer search.");
        // let mrs = MemRanges::from_radare_infos(&infos);
        // debug!("Checking that no range pointers exist.");
        // let v1 = ptr_search.get_pointer_range_vec();
        // assert_eq!(v1.len(), 0);
        //
        // // focus only on 'writable' memory
        // let v_mrs = mrs.get_mem_ranges();
        // let mut wv_mrs = Vec::new();
        // for mr in v_mrs.iter() {
        //     if mr.perm.find("w").is_some() {
        //         wv_mrs.push(mr.clone());
        //     }
        // }
        // debug!("Adding memranges to the pointer search.");
        // ptr_search.add_box_mem_ranges(&wv_mrs);
        // debug!("Checking that range pointers were created with mem ranges.");
        // let v2 = ptr_search.data_interface.get_pointer_range_vec();
        // // assert_eq!(v2.len() as u64, mrs.count());
        // debug!("Serializing a range pointers were created with mem ranges.");
        // let s = json!(**(v2.get(0).unwrap()));
        // println!("{}", s);
        // return Ok(());
    }

    let data_interface = Box::new(DataInterface::new_from_radare_info(&args.dmp, &infos, None));
    println!("{}", infos.items.get(0).unwrap());

    if args.interactive {
        return interactive_loop(
            regex_start.to_string(),
            regex_end.to_string(),
            args.output_path,
            data_interface.clone(),
        );
    }

    Ok(())
}
