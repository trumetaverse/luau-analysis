use serde;
use serde::Deserialize;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct RadareMemoryInfo {
    pub name: String,
    pub size: u64,
    pub vsize: u64,
    pub perm: String,
    pub paddr: u64,
    pub vaddr: u64,
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
            self.name, self.perm, self.paddr, self.size, self.vaddr, self.vsize
        )
    }
}

pub fn parse_radare_name(info: &String) -> RadareMemoryInfo {
    let name_split_vector: Vec<&str> = info.split(' ').collect::<Vec<&str>>();
    let mut paddr: u64 = 0;
    let mut _stype: u64 = 0;
    let mut _alloc: u64 = 0;
    let mut _state: u64 = 0;
    for vstr in name_split_vector.iter() {
        if vstr.starts_with("paddr") {
            let imm = *vstr.split('=').collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            paddr = v.unwrap();
        } else if vstr.starts_with("state") {
            let imm = *vstr.split('=').collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            _state = v.unwrap();
        } else if vstr.starts_with("allocation") {
            let imm = *vstr.split('=').collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            _alloc = v.unwrap();
        } else if vstr.starts_with("type") {
            let imm = *vstr.split('=').collect::<Vec<&str>>().get(1).unwrap();
            let v = u64::from_str_radix(imm.trim_start_matches("0x"), 16);
            _stype = v.unwrap();
        }
    }
    let name = *name_split_vector.last().unwrap();
    RadareMemoryInfo {
        name: name.to_string(),
        // size: info.size,
        size: 0,
        vsize: 0,
        // vaddr: info.address,
        paddr,
        // stype: stype,
        // state: state,
        // alloc_protection: alloc,
        // flags: info.flags.clone(),
        perm: "".to_string(),
        vaddr: 0,
    }
}

impl RadareMemoryInfos {
    pub fn from_radare_json(path: &PathBuf) -> RadareMemoryInfos {
        let text = std::fs::read_to_string(path).unwrap();
        serde_json::from_str::<RadareMemoryInfos>(&text).unwrap()
    }
}
