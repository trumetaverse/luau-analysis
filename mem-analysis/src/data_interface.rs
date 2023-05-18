use crate::buffer::DataBuffer;
use crate::memory::{MemRange, MemRanges};
use crate::pointers::PointerRange;
use crate::radare::RadareMemoryInfos;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::collections::HashMap;
use std::path::PathBuf;
use std::mem::{size_of};

use log::debug;
use serde;
use serde::Serialize;

#[derive(Debug, PartialEq, Clone)]
pub struct ReadValue {
    pub consumed: u64,
    pub value: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum ENDIAN {
    BIG,
    LITTLE,
}

#[derive(Debug, Clone, Serialize)]
pub struct VMemInfo {
    pub page_mask: u64,
    pub page_size: u64,
    pub word_sz: u8,
    pub alignment: u8,
    pub ptr_ranges: Box<HashMap<u64, Box<PointerRange>>>,
    pub ptr_lookup: Box<HashMap<u64, Box<PointerRange>>>,
    pub endian: ENDIAN,
}

#[warn(dead_code)]
impl VMemInfo {
    fn new() -> Self {
        VMemInfo {
            page_mask: 0xfffffffffffff000 as u64,
            page_size: 4096 as u64,
            word_sz: 8,
            alignment: 8,
            ptr_ranges: Box::new(HashMap::new()),
            ptr_lookup: Box::new(HashMap::new()),
            endian: ENDIAN::LITTLE,
        }
    }

    fn get_vaddr_base(&self, vaddr: &u64) -> Option<u64> {
        let cpage = self.get_page(vaddr);
        if self.ptr_lookup.contains_key(&cpage) {
            let ptr_range = &self.ptr_lookup.get(&cpage).unwrap();
            return Some(ptr_range.vstart);
        }
        return None;
    }

    fn get_paddr_base_from_vaddr(&self, vaddr: &u64) -> Option<u64> {
        let cpage = self.get_page(vaddr);
        if self.ptr_lookup.contains_key(&cpage) {
            let ptr_range = &self.ptr_lookup.get(&cpage).unwrap();
            return Some(ptr_range.pstart);
        }
        return None;
    }

    fn convert_vaddr_to_paddr(&self, vaddr: &u64) -> Option<u64> {
        let o_vaddr_base = self.get_vaddr_base(vaddr);
        if o_vaddr_base.is_none() {
            return None;
        }
        let vaddr_base = o_vaddr_base.unwrap();
        let paddr_base = self.get_paddr_base_from_vaddr(&vaddr_base).unwrap();
        return Some(paddr_base + (vaddr-vaddr_base))

    }

    fn get_page(&self, addr: &u64) -> u64 {
        return addr & self.page_mask;
    }

    #[warn(dead_code)]
    fn set_alignment(&mut self, o_alignment: Option<u8>) -> u8 {
        let alignment: u8 = match o_alignment {
            Some(a) => match a {
                0 => 0,
                1 => 1,
                2 => 2,
                4 => 4,
                8 => 8,
                16 => 16,
                _ => self.word_sz,
            },
            None => 4,
        };
        self.alignment = alignment;
        return self.alignment;
    }

    #[warn(dead_code)]
    fn set_word_sz(&mut self, o_word_sz: Option<u8>) -> u8 {
        let word_sz: u8 = match o_word_sz {
            Some(a) => match a {
                2 => 2,
                4 => 4,
                8 => 8,
                16 => 16,
                _ => 4,
            },
            None => 4,
        };
        self.word_sz = word_sz;
        return self.word_sz;
    }
    pub fn is_pointer_with_alignment(&self, vaddr: &u64) -> bool {
        if *vaddr % self.alignment as u64 != 0 {
            return false;
        }
        return self.contains_pointer_range(vaddr);
    }

    pub fn contains_pointer_range(&self, vaddr: &u64) -> bool {
        let cpage = vaddr & self.page_mask;
        if self.ptr_ranges.contains_key(&cpage) {
            return true;
        }
        return self.ptr_lookup.contains_key(&cpage);
    }

    pub fn get_pointer_range_by_vaddr(&self, vaddr: u64) -> Option<Box<PointerRange>> {
        let cpage = vaddr & self.page_mask;
        if !self.ptr_lookup.contains_key(&cpage) {
            return None;
        }
        return Some(self.ptr_lookup.get(&cpage).unwrap().clone());
    }

    pub fn create_pointer_range(&mut self, paddr: u64, vaddr: u64, size: u64) -> Box<PointerRange> {
        debug!(
            "Creating a pointer range for paddr: {:08x} vaddr: {:08x} of size: {:08x}",
            paddr, vaddr, size
        );
        let ptr_range = Box::new(PointerRange::new(paddr, paddr + size, vaddr, vaddr + size));
        self.add_pointer_range(ptr_range.clone());
        return ptr_range.clone();
    }

    pub fn add_pointer_range(&mut self, ptr_range: Box<PointerRange>) -> bool {
        let mut cpage = ptr_range.vstart & self.page_mask;

        if self.ptr_lookup.contains_key(&cpage) {
            return false;
        }
        debug!(
            "Adding the pointer range: {:08x} for {:08x}",
            ptr_range.vstart, cpage
        );
        self.ptr_ranges.insert(cpage, ptr_range.clone());

        let vaddr_end = ptr_range.vend;
        debug!(
            "Updating the lookup cache: {:08x} for {:08x}",
            ptr_range.vstart, cpage
        );
        while cpage < vaddr_end {
            self.ptr_lookup.insert(cpage, ptr_range.clone());
            cpage = (self.page_size + cpage) & self.page_mask
        }
        debug!(
            "Done updating the lookup cache: {:08x} with a len() : {:08x}",
            ptr_range.vstart,
            self.ptr_lookup.len()
        );
        return true;
    }
    pub fn get_pointer_range_vec(&self) -> Vec<Box<PointerRange>> {
        let mut v_ranges = Vec::new();
        for (_key, pr) in self.ptr_ranges.iter() {
            v_ranges.push(pr.clone());
        }
        return v_ranges;
    }
}

#[derive(Debug, Clone)]
pub struct DataInterface {
    pub buffer: Box<DataBuffer>,
    pub mem_ranges: Box<MemRanges>,
    pub vmem_info: Box<VMemInfo>,
}

#[warn(dead_code)]
impl DataInterface {
    // pub fn get_vmem_info(self) -> Box<&mut VMemInfo> {
    //     return self.vmem_info.clone();
    // }

    pub fn convert_vaddr_to_paddr(&self, vaddr: &u64) -> Option<u64> {
        return self.vmem_info.convert_vaddr_to_paddr(vaddr)
    }
    pub fn get_vaddr_section_name(&self, vaddr: u64) -> Option<String> {
        return self.mem_ranges.get_vaddr_section_name(vaddr);
    }

    pub fn get_paddr_section_name(&self, paddr: u64) -> Option<String> {
        return self.mem_ranges.get_paddr_section_name(paddr);
    }
    pub fn get_vaddr_base_from_vaddr(&self, vaddr: &u64) -> Option<u64> {
        return self.get_vaddr_base(vaddr);
    }
    pub fn get_vaddr_base(&self, vaddr: &u64) -> Option<u64> {
        return self.vmem_info.get_vaddr_base(vaddr);
    }

    pub fn get_paddr_base_from_vaddr(&self, vaddr: &u64) -> Option<u64> {
        return self.vmem_info.get_paddr_base_from_vaddr(vaddr);
    }

    pub fn new_from_radare_info(
        bin_file: &PathBuf,
        radare_infos: &RadareMemoryInfos,
        o_vmem_info: Option<VMemInfo>,
    ) -> Self {
        let mut vmem_info = match o_vmem_info {
            Some(v) => Box::new(v.clone()),
            None => Box::new(VMemInfo::new()),
        };
        let mem_ranges = Box::new(MemRanges::from_radare_infos(&radare_infos));

        for (_k, mr) in mem_ranges.vmem_ranges.iter() {
            let size = &mr.size;
            let paddr = &mr.paddr_start;
            let vaddr = &mr.vaddr_start;
            vmem_info.create_pointer_range(*paddr, *vaddr, *size);
        }
        DataInterface {
            buffer: Box::new(DataBuffer::from_pathbuf(bin_file, true)),
            mem_ranges: mem_ranges,
            vmem_info: vmem_info,
        }
    }

    pub fn shared_slice_paddr(&self, paddr: u64, read_size: u64) -> Option<&[u8]> {
        let o_mr = self.mem_ranges.get_paddr_range(paddr);
        if o_mr.is_none() {
            return None;
        }
        let mr: Box<MemRange> = o_mr.unwrap();
        let paddr_start = mr.paddr_start;
        let psize = mr.size;
        if paddr + read_size < paddr_start + psize {
            return self.buffer.get_shared_slice_from(paddr, Some(read_size));
        }
        return None;
    }

    pub fn is_paddr_ptr(&self, paddr: u64) -> bool {
        return self.mem_ranges.pmem_ranges.contains_key(&paddr);
    }

    pub fn is_vaddr_ptr(&self, vaddr: u64) -> bool {
        return self.vmem_info.is_pointer_with_alignment(&vaddr);
    }

    pub fn shared_slice_vaddr(&self, vaddr: u64, read_size: u64) -> Option<&[u8]> {
        let o_sb = self.shared_buffer_vaddr(vaddr);
        if o_sb.is_none() {
            return None;
        }

        let sb = o_sb.unwrap();
        let mr: Box<MemRange> = self.mem_ranges.get_vaddr_range(vaddr).unwrap();

        let offset = vaddr - mr.vaddr_start;
        if mr.paddr_start + offset + read_size < mr.paddr_start + mr.size {
            return Some(&sb[offset as usize..(offset + read_size) as usize]);
        }
        return None;
    }

    pub fn shared_buffer_vaddr(&self, vaddr: u64) -> Option<&[u8]> {
        let o_mr = self.mem_ranges.get_vaddr_range(vaddr);
        if o_mr.is_none() {
            return None;
        }
        let mr: Box<MemRange> = o_mr.unwrap().clone();

        let paddr_base = mr.paddr_start;
        let vsize = mr.vsize;
        let vaddr_base = mr.vaddr_start;
        assert_eq!(true, vaddr_base <= vaddr && vaddr < vaddr_base + vsize);
        return self.buffer.get_shared_slice_from(paddr_base, Some(vsize));
    }

    pub fn shared_buffer_paddr(&self, paddr: u64) -> Option<&[u8]> {
        return self.buffer.get_shared_slice_from(paddr, None);
    }

    // pub fn read_struct(&self, vaddr: u64, stype: impl BinRead) -> Option<impl BinRead> {
    //     let o_sbo = self.shared_buffer_vaddr(vaddr);
    //     let offset = self.
    //     let result = stype::read(&sbo);
    // }

    pub fn can_read_buffer(&self, buffer: &[u8], pos: u64, size: u64) -> bool {
        return (pos + size) < (buffer.len() as u64);
    }

    pub fn can_read_buffer_at(&self, vaddr: u64, size: u64) -> bool {
        let o_mr = self.mem_ranges.get_vaddr_range(vaddr);
        if o_mr.is_none() {
            return false;
        }
        let mr: Box<MemRange> = o_mr.unwrap().clone();
        let vaddr_base = mr.vaddr_start;
        let vaddr_end = mr.vaddr_start + mr.vsize;
        return vaddr_base <= vaddr && vaddr + size < vaddr_end;
    }

    pub fn read_word_size_value(&self, buffer: &[u8]) -> Option<ReadValue> {
        let size = self.vmem_info.word_sz as u64;
        // debug!("Reading {} bytes from buf[{:08x}]", size, 0  );
        if size > buffer.len() as u64 {
            // debug!("Unable to read {} bytes from buf[{:08x}]", size, 0  );
            return None;
        }

        let value: Option<u64> = match self.vmem_info.endian {
            ENDIAN::BIG => match size {
                1 => Some(buffer[0] as u64),
                2 => Some(BigEndian::read_u16(buffer) as u64),
                4 => Some(BigEndian::read_u32(buffer) as u64),
                8 => Some(BigEndian::read_u64(buffer) as u64),
                16 => Some(BigEndian::read_u128(buffer) as u64),
                _ => None,
            },
            ENDIAN::LITTLE => match size {
                1 => Some(buffer[0] as u64),
                2 => Some(LittleEndian::read_u16(buffer) as u64),
                4 => Some(LittleEndian::read_u32(buffer) as u64),
                8 => Some(LittleEndian::read_u64(buffer) as u64),
                16 => Some(LittleEndian::read_u128(buffer) as u64),
                _ => None,
            },
        };

        if value.is_some() {
            return Some(ReadValue {
                consumed: size,
                value: value.unwrap(),
            });
        }
        return None;
    }

    pub fn read_word_size_value_at_pos(&self, buffer: &[u8], pos: u64) -> Option<ReadValue> {
        if pos < buffer.len() as u64 {
            return self.read_word_size_value(&buffer[pos as usize..]);
        }
        return None;
    }

    pub fn read_word_size_value_at_vaddr(&self, vaddr: u64) -> Option<ReadValue> {
        // debug!("Attempting to get range for vaddr: {:08x}", vaddr  );
        let o_vaddr_base = self.get_vaddr_base(&vaddr);
        if o_vaddr_base.is_none() {
            // debug!("Failed to find the range for vaddr: {:08x}", vaddr  );
            return None;
        }
        // debug!("Attempting to get the shared memory for vaddr: {:08x}", vaddr  );
        let o_fbuffer = self.shared_buffer_vaddr(vaddr);
        if o_fbuffer.is_none() {
            // debug!("Failed to get the shared memory for vaddr: {:08x}", vaddr  );
            return None;
        }
        let pos = vaddr - o_vaddr_base.unwrap();
        // debug!("Attempting to read the shared memory for vaddr: buffer[{:08x}] ({})", pos, vaddr  );
        return self.read_word_size_value_at_pos(o_fbuffer.unwrap(), pos);
    }

    pub fn get_vaddr_end(&self, vaddr: u64) -> Option<u64> {
        let o_mr = self.mem_ranges.get_vaddr_range(vaddr);
        if o_mr.is_none() {
            return None;
        }
        let mr: Box<MemRange> = o_mr.unwrap().clone();
        return Some(mr.vaddr_start + mr.vsize);
    }

    pub fn read_i64(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<i64> {
        let mut endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<i64>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_i64(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_i64(buffer)),
            };
        }


    pub fn read_u64(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<u64> {
        let endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            let _endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<i64>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_u64(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_u64(buffer)),
        };
    }

    pub fn read_i32(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<i32> {
        let mut endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<i32>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_i32(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_i32(buffer)),
        };
    }


    pub fn read_u32(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<u32> {
        let mut endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<u32>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_u32(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_u32(buffer)),
        };
    }
    pub fn read_i16(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<i64> {
        let endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            let _endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<u16>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_i64(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_i64(buffer)),
        };
    }

    pub fn read_u16(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<u16> {
        let endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            let _endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<u16>() {
            return None;
        }

        return match endian {
            ENDIAN::BIG => Some(BigEndian::read_u16(buffer)),
            ENDIAN::LITTLE => Some(LittleEndian::read_u16(buffer)),
        };
    }

    pub fn read_u8(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<u8> {
        let _endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            let _endian = o_endian.unwrap();
        }

        if buffer.len() < size_of::<u8>() {
            return None;
        }

        return Some(buffer[0]);
    }
    pub fn read_i8(&self, buffer: &[u8], o_endian: Option<ENDIAN>) -> Option<i8> {
        let _endian = self.vmem_info.endian.clone();
        if o_endian.is_some() {
            let _endian = o_endian.unwrap();
        }
        if buffer.len() < size_of::<u8>() {
            return None;
        }
        return Some(buffer[0] as i8);
    }
}
