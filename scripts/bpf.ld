MEMORY
{
  X86 : ORIGIN = 0x900000000, LENGTH = 0x1000000
  BPF : ORIGIN = 0x100000000, LENGTH = 0x1000000
}

REGION_ALIAS("REGION_X86", X86);
REGION_ALIAS("REGION_BPF", BPF);

SECTIONS
{
  .bpf : { *(.bpf) } > REGION_BPF
  .text : { *(.text) } > REGION_X86
  .eh_frame : { *(.eh_frame) } > REGION_X86
}

ENTRY(entrypoint)
