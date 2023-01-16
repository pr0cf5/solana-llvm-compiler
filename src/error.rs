#[derive(Debug)]
pub enum Error {
    EbpfError(String),
    LlvmError(String),
    ElfError(String),
}

impl Error {
    pub fn ebpf_error<T: ToString>(e: &T) -> Self {
        Self::EbpfError(e.to_string())
    }

    pub fn llvm_error<T: ToString>(e: &T) -> Self {
        Self::LlvmError(e.to_string())
    }

    pub fn elf_error<T: ToString>(e: &T) -> Self {
        Self::ElfError(e.to_string())
    }
}
