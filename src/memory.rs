
pub struct MemorySection {
    pub virt_base_address : u64,
    pub phys_base_address : u64,
    pub size: u64,
    pub section_name: String,
    pub flags : String,
    pub data : Vec<u8>,
}

