mod error;
mod jit;

use clap::Parser;
use jit::jit_compile;
use std::fs::{read, write};

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    input_file: String,
    #[arg(short, long)]
    output_file: String,
}

fn main() {
    let args = Cli::parse();
    let elf_bytes = read(args.input_file).expect("Failed to read input file");
    let jit_compiled_bytes = jit_compile(&elf_bytes).expect("Failed to jit compile");
    write(args.output_file, jit_compiled_bytes).expect("Failed to write to output file");
    println!("[+] Done");
}
