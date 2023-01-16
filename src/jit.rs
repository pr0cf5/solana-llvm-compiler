use solana_rbpf::elf::Executable;
use solana_rbpf::jit_llvm::jit_compile_llvm;
use solana_rbpf::syscalls::bpf_syscall_u64;
use solana_rbpf::vm::{BuiltInProgram, Config, TestContextObject};
use std::sync::Arc;

use crate::error::Error;

const SOLANA_SYSCALLS: &[&str] = &[
    "abort",
    "sol_panic_",
    "sol_log_",
    "sol_log_64_",
    "sol_log_compute_units_",
    "sol_log_pubkey",
    "sol_create_program_address",
    "sol_try_find_program_address",
    "sol_sha256",
    "sol_keccak256",
    "sol_secp256k1_recover",
    "sol_blake3",
    "sol_curve_validate_point",
    "sol_curve_group_op",
    "sol_get_clock_sysvar",
    "sol_get_epoch_schedule_sysvar",
    "sol_get_fees_sysvar",
    "sol_get_rent_sysvar",
    "sol_memcpy_",
    "sol_memmove_",
    "sol_memcmp_",
    "sol_memset_",
    "sol_invoke_signed_c",
    "sol_invoke_signed_rust",
    "sol_alloc_free_",
    "sol_set_return_data",
    "sol_get_return_data",
    "sol_log_data",
    "sol_get_processed_sibling_instruction",
    "sol_get_stack_height",
];

pub fn jit_compile(elf_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut config = Config::default();
    config.enable_elf_vaddr = false;
    config.dynamic_stack_frames = false;
    config.enable_instruction_tracing = false;
    config.enable_instruction_meter = false;
    config.sanitize_user_provided_values = false;
    let mut loader = BuiltInProgram::<TestContextObject>::new_loader(config);
    for &syscall_name in SOLANA_SYSCALLS.iter() {
        loader
            .register_function_by_name(syscall_name, bpf_syscall_u64)
            .map_err(|e| Error::ebpf_error(&e))?;
    }

    let executable =
        Executable::from_elf(elf_bytes, Arc::new(loader)).map_err(|e| Error::ebpf_error(&e))?;
    jit_compile_llvm(&executable).map_err(|e| Error::llvm_error(&e))
}
