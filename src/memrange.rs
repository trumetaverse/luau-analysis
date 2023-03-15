

pub struct MemRange {
    vaddr_start: u64,
    paddr_start: u64,
    vsize : u64,
    size: u64,
    filename: String,
    word_sz: u8,
    data : &[u8],

}

trait Memory {
    fn in_range(&self, addr : u64) -> bool ;
}

impl Memory for MemRange {
    fn in_range(&self, addr: u64) -> bool {
        if  self.vaddr_start <= addr && addr <= self.vaddr_start + self.vsize {
            return true;
        }
        return false;
    }
}