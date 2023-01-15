use solana_rbpf::elf::Executable;
use solana_rbpf::jit_llvm::jit_compile_llvm;
use solana_rbpf::vm::{BuiltInProgram, Config, TestContextObject};
use std::sync::Arc;

use crate::error::Error;

pub fn jit_compile(elf_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut config = Config::default();
    config.enable_elf_vaddr = false;
    config.dynamic_stack_frames = false;
    config.enable_instruction_tracing = false;
    config.enable_instruction_meter = false;
    config.sanitize_user_provided_values = false;
    let loader = Arc::new(BuiltInProgram::<TestContextObject>::new_loader(config));
    let executable = Executable::from_elf(elf_bytes, loader).map_err(|e| Error::ebpf_error(&e))?;
    let (_text_vaddr, text_bytes) = executable.get_text_bytes();
    jit_compile_llvm(text_bytes).map_err(|e| Error::llvm_error(&e))
}
