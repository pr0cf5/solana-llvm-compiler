//! eBPF to LLVM IR compilation
use inkwell::basic_block::BasicBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::intrinsics::Intrinsic;
use inkwell::module::Module;
use inkwell::passes::{PassManager, PassManagerBuilder};
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetTriple,
};
use inkwell::types::{IntType, PointerType};
use inkwell::values::{FunctionValue, IntValue, PointerValue};
use inkwell::OptimizationLevel;
use inkwell::{AddressSpace, IntPredicate};

use std::collections::{BTreeMap, HashMap};

use crate::ebpf::{self, Insn};
use crate::elf::Executable;
use crate::error::EbpfError;
use crate::static_analysis::Analysis;
use crate::vm::ContextObject;

/// JIT compiler abstraction for ebpf
pub struct LLVMJitCompiler<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    /// map of starting pc -> function value
    function_map_by_pc: BTreeMap<usize, FunctionValue<'ctx>>,
    /// map of internal function hash -> function value
    function_map_by_hash: BTreeMap<u32, FunctionValue<'ctx>>,
    syscall_map: BTreeMap<u32, FunctionValue<'ctx>>,
}

struct PerFunctionEnv<'ctx> {
    /// current function in compilation
    current_function: FunctionValue<'ctx>,
    /// maps ebpf register to LLVM local allocation
    register_map: HashMap<u8, PointerValue<'ctx>>,
    /// maps starting pc to block
    basic_block_map: HashMap<usize, BasicBlock<'ctx>>,
}

#[allow(dead_code)]
enum Value {
    Register(u8),
    RegisterIndirect(u8, i32, bool),
    RegisterPlusConstant32(u8, i32, bool),
    RegisterPlusConstant64(u8, i64, bool),
    Constant64(i64, bool),
}

#[derive(Copy, Clone)]
enum MemoryOperandSize {
    One,
    Two,
    Four,
    Eight,
}

enum NextTranslationTask<'ctx> {
    NextPc {
        target_pc: usize,
    },
    Jmp {
        target_pc: usize,
    },
    JmpCond {
        predicate: IntValue<'ctx>,
        target_if: usize,
        target_else: usize,
    },
    Exit,
}

impl<'ctx> LLVMJitCompiler<'ctx> {
    fn intptr_type(&self, operand_size: MemoryOperandSize) -> PointerType<'ctx> {
        match operand_size {
            MemoryOperandSize::One => self.context.i8_type().ptr_type(AddressSpace::from(64)),
            MemoryOperandSize::Two => self.context.i16_type().ptr_type(AddressSpace::from(64)),
            MemoryOperandSize::Four => self.context.i32_type().ptr_type(AddressSpace::from(64)),
            MemoryOperandSize::Eight => self.context.i64_type().ptr_type(AddressSpace::from(64)),
        }
    }

    fn int_type(&self, operand_size: MemoryOperandSize) -> IntType<'ctx> {
        match operand_size {
            MemoryOperandSize::One => self.context.i8_type(),
            MemoryOperandSize::Two => self.context.i16_type(),
            MemoryOperandSize::Four => self.context.i32_type(),
            MemoryOperandSize::Eight => self.context.i64_type(),
        }
    }

    fn translate_write_ebpf_register(
        &self,
        ebpf_register_id: u8,
        value: IntValue,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let &ptr_value = per_function_env
            .register_map
            .get(&ebpf_register_id)
            .unwrap();
        self.builder.build_store(ptr_value, value);
        Ok(())
    }

    fn translate_read_ebpf_register(
        &self,
        ebpf_register_id: u8,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<IntValue<'ctx>, EbpfError> {
        let &src_ptr_value = per_function_env
            .register_map
            .get(&ebpf_register_id)
            .unwrap();
        let loaded_value = self.builder.build_load(src_ptr_value, "").into_int_value();
        Ok(loaded_value)
    }

    fn translate_memory_store(
        &self,
        src_ptr: IntValue,
        value: IntValue,
        operand_size: MemoryOperandSize,
    ) -> Result<(), EbpfError> {
        let intptr_type = self.intptr_type(operand_size);
        let int_type = self.int_type(operand_size);
        let src_ptr_casted = self.builder.build_int_to_ptr(src_ptr, intptr_type, "");
        let value_casted = self.builder.build_int_cast(value, int_type, "");
        self.builder.build_store(src_ptr_casted, value_casted);
        Ok(())
    }

    fn translate_memory_load(
        &self,
        src_ptr: IntValue<'ctx>,
        operand_size: MemoryOperandSize,
    ) -> Result<IntValue<'ctx>, EbpfError> {
        let intptr_type = self.intptr_type(operand_size);
        let src_ptr_casted = self.builder.build_int_to_ptr(src_ptr, intptr_type, "");
        let loaded_value = self.builder.build_load(src_ptr_casted, "").into_int_value();
        Ok(loaded_value)
    }

    fn translate_value(
        &self,
        value: Value,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<IntValue<'ctx>, EbpfError> {
        // for now, don't translate the address, and simply move it to a register
        match value {
            Value::RegisterPlusConstant64(reg, offset, _) => {
                let base = self.translate_read_ebpf_register(reg, per_function_env)?;
                let offset_value = self.context.i64_type().const_int(offset as u64, true);
                Ok(self.builder.build_int_add(base, offset_value, ""))
            }
            Value::Constant64(constant, _) => {
                Ok(self.context.i64_type().const_int(constant as u64, true))
            }
            _ => panic!("unreachable"),
        }
    }

    fn new(context: &'ctx Context) -> Result<Self, ()> {
        let module = context.create_module("main");
        let builder = context.create_builder();

        Ok(Self {
            context: &context,
            module,
            builder,
            function_map_by_pc: BTreeMap::new(),
            function_map_by_hash: BTreeMap::new(),
            syscall_map: BTreeMap::new(),
        })
    }

    fn translate_instruction_memory_load_reg(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let operand_size = match insn.opc {
            ebpf::LD_B_REG => MemoryOperandSize::One,
            ebpf::LD_H_REG => MemoryOperandSize::Two,
            ebpf::LD_W_REG => MemoryOperandSize::Four,
            ebpf::LD_DW_REG => MemoryOperandSize::Eight,
            _ => panic!("unreachable"),
        };
        let addr = self.translate_value(
            Value::RegisterPlusConstant64(insn.src, insn.off as i64, true),
            per_function_env,
        )?;
        let value_raw = self.translate_memory_load(addr, operand_size)?;
        let value = self
            .builder
            .build_int_cast(value_raw, self.context.i64_type(), "");
        self.translate_write_ebpf_register(insn.dst, value, per_function_env)?;
        Ok(())
    }

    fn translate_instruction_memory_store_imm(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let operand_size = match insn.opc {
            ebpf::ST_B_IMM => MemoryOperandSize::One,
            ebpf::ST_H_IMM => MemoryOperandSize::Two,
            ebpf::ST_W_IMM => MemoryOperandSize::Four,
            ebpf::ST_DW_IMM => MemoryOperandSize::Eight,
            _ => panic!("unreachable"),
        };
        let addr = self.translate_value(
            Value::RegisterPlusConstant64(insn.dst, insn.off as i64, true),
            per_function_env,
        )?;
        let value = self.context.i64_type().const_int(insn.imm as u64, true);
        self.translate_memory_store(addr, value, operand_size)?;
        Ok(())
    }

    fn translate_instruction_memory_store_reg(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let operand_size = match insn.opc {
            ebpf::ST_B_REG => MemoryOperandSize::One,
            ebpf::ST_H_REG => MemoryOperandSize::Two,
            ebpf::ST_W_REG => MemoryOperandSize::Four,
            ebpf::ST_DW_REG => MemoryOperandSize::Eight,
            _ => panic!("unreachable"),
        };
        let addr = self.translate_value(
            Value::RegisterPlusConstant64(insn.dst, insn.off as i64, true),
            per_function_env,
        )?;
        let value = self.translate_read_ebpf_register(insn.src, per_function_env)?;
        self.translate_memory_store(addr, value, operand_size)?;
        Ok(())
    }

    fn translate_instruction_alu32_imm(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let imm_value = self.context.i64_type().const_int(insn.imm as u64, true);
        let dst_reg_value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let store_value = match insn.opc {
            ebpf::ADD32_IMM => self.builder.build_int_add(dst_reg_value, imm_value, ""),
            ebpf::SUB32_IMM => self.builder.build_int_sub(dst_reg_value, imm_value, ""),
            ebpf::MUL32_IMM => self.builder.build_int_mul(dst_reg_value, imm_value, ""),
            ebpf::DIV32_IMM => self
                .builder
                .build_int_unsigned_div(dst_reg_value, imm_value, ""),
            ebpf::SDIV32_IMM => self
                .builder
                .build_int_signed_div(dst_reg_value, imm_value, ""),
            ebpf::MOD32_IMM => self
                .builder
                .build_int_unsigned_rem(dst_reg_value, imm_value, ""),
            ebpf::OR32_IMM => self.builder.build_or(dst_reg_value, imm_value, ""),
            ebpf::AND32_IMM => self.builder.build_and(dst_reg_value, imm_value, ""),
            ebpf::LSH32_IMM => self.builder.build_left_shift(dst_reg_value, imm_value, ""),
            ebpf::RSH32_IMM => self
                .builder
                .build_right_shift(dst_reg_value, imm_value, false, ""),
            ebpf::XOR32_IMM => self.builder.build_xor(dst_reg_value, imm_value, ""),
            ebpf::ARSH32_IMM => self
                .builder
                .build_right_shift(dst_reg_value, imm_value, true, ""),
            _ => panic!("unreachable"),
        };
        self.translate_write_ebpf_register(insn.dst, store_value, per_function_env)?;
        Ok(())
    }

    fn translate_instruction_alu32_reg(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let src_reg_value = self.translate_read_ebpf_register(insn.src, per_function_env)?;
        let dst_reg_value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let store_value = match insn.opc {
            ebpf::ADD32_REG => self.builder.build_int_add(dst_reg_value, src_reg_value, ""),
            ebpf::SUB32_REG => self.builder.build_int_sub(dst_reg_value, src_reg_value, ""),
            ebpf::MUL32_REG => self.builder.build_int_mul(dst_reg_value, src_reg_value, ""),
            ebpf::DIV32_REG => {
                self.builder
                    .build_int_unsigned_div(dst_reg_value, src_reg_value, "")
            }
            ebpf::SDIV32_REG => self
                .builder
                .build_int_signed_div(dst_reg_value, src_reg_value, ""),
            ebpf::MOD32_REG => {
                self.builder
                    .build_int_unsigned_rem(dst_reg_value, src_reg_value, "")
            }
            ebpf::OR32_REG => self.builder.build_or(dst_reg_value, src_reg_value, ""),
            ebpf::AND32_REG => self.builder.build_and(dst_reg_value, src_reg_value, ""),
            ebpf::LSH32_REG => self
                .builder
                .build_left_shift(dst_reg_value, src_reg_value, ""),
            ebpf::RSH32_REG => {
                self.builder
                    .build_right_shift(dst_reg_value, src_reg_value, false, "")
            }
            ebpf::XOR32_REG => self.builder.build_xor(dst_reg_value, src_reg_value, ""),
            ebpf::ARSH32_REG => {
                self.builder
                    .build_right_shift(dst_reg_value, src_reg_value, true, "")
            }
            _ => panic!("unreachable"),
        };
        self.translate_write_ebpf_register(insn.dst, store_value, per_function_env)?;
        Ok(())
    }

    fn translate_instruction_alu64_imm(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let imm_value = self.context.i64_type().const_int(insn.imm as u64, true);
        let dst_reg_value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let store_value = match insn.opc {
            ebpf::ADD64_IMM => self.builder.build_int_add(dst_reg_value, imm_value, ""),
            ebpf::SUB64_IMM => self.builder.build_int_sub(dst_reg_value, imm_value, ""),
            ebpf::MUL64_IMM => self.builder.build_int_mul(dst_reg_value, imm_value, ""),
            ebpf::DIV64_IMM => self
                .builder
                .build_int_unsigned_div(dst_reg_value, imm_value, ""),
            ebpf::SDIV64_IMM => self
                .builder
                .build_int_signed_div(dst_reg_value, imm_value, ""),
            ebpf::MOD64_IMM => self
                .builder
                .build_int_unsigned_rem(dst_reg_value, imm_value, ""),
            ebpf::OR64_IMM => self.builder.build_or(dst_reg_value, imm_value, ""),
            ebpf::AND64_IMM => self.builder.build_and(dst_reg_value, imm_value, ""),
            ebpf::LSH64_IMM => self.builder.build_left_shift(dst_reg_value, imm_value, ""),
            ebpf::RSH64_IMM => self
                .builder
                .build_right_shift(dst_reg_value, imm_value, false, ""),
            ebpf::XOR64_IMM => self.builder.build_xor(dst_reg_value, imm_value, ""),
            ebpf::ARSH64_IMM => self
                .builder
                .build_right_shift(dst_reg_value, imm_value, true, ""),
            _ => panic!("unreachable"),
        };
        self.translate_write_ebpf_register(insn.dst, store_value, per_function_env)?;
        Ok(())
    }

    fn translate_instruction_alu64_reg(
        &self,
        insn: Insn,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<(), EbpfError> {
        let src_reg_value = self.translate_read_ebpf_register(insn.src, per_function_env)?;
        let dst_reg_value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let store_value = match insn.opc {
            ebpf::ADD64_REG => self.builder.build_int_add(dst_reg_value, src_reg_value, ""),
            ebpf::SUB64_REG => self.builder.build_int_sub(dst_reg_value, src_reg_value, ""),
            ebpf::MUL64_REG => self.builder.build_int_mul(dst_reg_value, src_reg_value, ""),
            ebpf::DIV64_REG => {
                self.builder
                    .build_int_unsigned_div(dst_reg_value, src_reg_value, "")
            }
            ebpf::SDIV64_REG => self
                .builder
                .build_int_signed_div(dst_reg_value, src_reg_value, ""),
            ebpf::MOD64_REG => {
                self.builder
                    .build_int_unsigned_rem(dst_reg_value, src_reg_value, "")
            }
            ebpf::OR64_REG => self.builder.build_or(dst_reg_value, src_reg_value, ""),
            ebpf::AND64_REG => self.builder.build_and(dst_reg_value, src_reg_value, ""),
            ebpf::LSH64_REG => self
                .builder
                .build_left_shift(dst_reg_value, src_reg_value, ""),
            ebpf::RSH64_REG => {
                self.builder
                    .build_right_shift(dst_reg_value, src_reg_value, false, "")
            }
            ebpf::XOR64_REG => self.builder.build_xor(dst_reg_value, src_reg_value, ""),
            ebpf::ARSH64_REG => {
                self.builder
                    .build_right_shift(dst_reg_value, src_reg_value, true, "")
            }
            _ => panic!("unreachable"),
        };
        self.translate_write_ebpf_register(insn.dst, store_value, per_function_env)?;
        Ok(())
    }

    fn translate_instruction_jump_imm(
        &self,
        insn: Insn,
        target_if: usize,
        target_else: usize,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<NextTranslationTask, EbpfError> {
        let predicate = match insn.opc {
            ebpf::JEQ_IMM => IntPredicate::EQ,
            ebpf::JGT_IMM => IntPredicate::UGT,
            ebpf::JGE_IMM => IntPredicate::UGE,
            ebpf::JLT_IMM => IntPredicate::ULT,
            ebpf::JLE_IMM => IntPredicate::ULE,
            ebpf::JNE_IMM => IntPredicate::NE,
            ebpf::JSGT_IMM => IntPredicate::SGT,
            ebpf::JSGE_IMM => IntPredicate::SGE,
            ebpf::JSLT_IMM => IntPredicate::SLT,
            ebpf::JSLE_IMM => IntPredicate::SLE,
            _ => panic!("unreachable"),
        };
        let lhs = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let rhs = self.context.i64_type().const_int(insn.imm as u64, true);
        let predicate = self.builder.build_int_compare(predicate, lhs, rhs, "");
        return Ok(NextTranslationTask::JmpCond {
            predicate,
            target_if,
            target_else,
        });
    }

    fn translate_instruction_jump_reg(
        &self,
        insn: Insn,
        target_if: usize,
        target_else: usize,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<NextTranslationTask, EbpfError> {
        let predicate = match insn.opc {
            ebpf::JEQ_REG => IntPredicate::EQ,
            ebpf::JGT_REG => IntPredicate::UGT,
            ebpf::JGE_REG => IntPredicate::UGE,
            ebpf::JLT_REG => IntPredicate::ULT,
            ebpf::JLE_REG => IntPredicate::ULE,
            ebpf::JNE_REG => IntPredicate::NE,
            ebpf::JSGT_REG => IntPredicate::SGT,
            ebpf::JSGE_REG => IntPredicate::SGE,
            ebpf::JSLT_REG => IntPredicate::SLT,
            ebpf::JSLE_REG => IntPredicate::SLE,
            _ => panic!("unreachable"),
        };
        let lhs = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
        let rhs = self.translate_read_ebpf_register(insn.src, per_function_env)?;
        let predicate = self.builder.build_int_compare(predicate, lhs, rhs, "");
        return Ok(NextTranslationTask::JmpCond {
            predicate,
            target_if,
            target_else,
        });
    }

    fn translate_instruction(
        &self,
        analysis: &Analysis,
        mut pc: usize,
        per_function_env: &PerFunctionEnv<'ctx>,
    ) -> Result<NextTranslationTask, EbpfError> {
        let insn = analysis.instructions.get(pc).unwrap().clone();
        let target_pc = (pc as isize + insn.off as isize + 1) as usize;

        match insn.opc {
            // because this instruction takes two instructions, it is handled separately
            ebpf::LD_DW_IMM => {
                self.translate_write_ebpf_register(
                    insn.dst,
                    self.context.i64_type().const_int(insn.imm as u64, true),
                    per_function_env,
                )?;
            }
            ebpf::LD_B_REG | ebpf::LD_H_REG | ebpf::LD_W_REG | ebpf::LD_DW_REG => {
                self.translate_instruction_memory_load_reg(insn, per_function_env)?;
            }
            // BPF_ST class
            ebpf::ST_B_IMM | ebpf::ST_H_IMM | ebpf::ST_W_IMM | ebpf::ST_DW_IMM => {
                self.translate_instruction_memory_store_imm(insn, per_function_env)?;
            }
            // BPF_STX class
            ebpf::ST_B_REG | ebpf::ST_H_REG | ebpf::ST_W_REG | ebpf::ST_DW_REG => {
                self.translate_instruction_memory_store_reg(insn, per_function_env)?;
            }
            // BPF_ALU class
            ebpf::ADD32_IMM
            | ebpf::SUB32_IMM
            | ebpf::MUL32_IMM
            | ebpf::DIV32_IMM
            | ebpf::SDIV32_IMM
            | ebpf::MOD32_IMM
            | ebpf::OR32_IMM
            | ebpf::AND32_IMM
            | ebpf::LSH32_IMM
            | ebpf::RSH32_IMM
            | ebpf::XOR32_IMM
            | ebpf::ARSH32_IMM => {
                self.translate_instruction_alu32_imm(insn, per_function_env)?;
            }
            ebpf::ADD32_REG
            | ebpf::SUB32_REG
            | ebpf::MUL32_REG
            | ebpf::DIV32_REG
            | ebpf::SDIV32_REG
            | ebpf::MOD32_REG
            | ebpf::OR32_REG
            | ebpf::AND32_REG
            | ebpf::LSH32_REG
            | ebpf::RSH32_REG
            | ebpf::XOR32_REG
            | ebpf::ARSH32_REG => {
                self.translate_instruction_alu32_reg(insn, per_function_env)?;
            }
            ebpf::NEG32 => {
                let value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                let negated = self.builder.build_int_neg(value, "");
                self.translate_write_ebpf_register(insn.dst, negated, per_function_env)?;
            }
            ebpf::MOV32_IMM => {
                let imm_value = self.context.i64_type().const_int(insn.imm as u64, true);
                self.translate_write_ebpf_register(insn.dst, imm_value, per_function_env)?;
            }
            ebpf::MOV32_REG => {
                let src_reg_value =
                    self.translate_read_ebpf_register(insn.src, per_function_env)?;
                self.translate_write_ebpf_register(insn.dst, src_reg_value, per_function_env)?;
            }
            ebpf::LE => match insn.imm {
                16 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let mask = self.context.i64_type().const_int(u16::MAX.into(), false);
                    let masked = self.builder.build_and(dst_reg_value, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                32 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let mask = self.context.i64_type().const_int(u32::MAX.into(), false);
                    let masked = self.builder.build_and(dst_reg_value, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                64 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let mask = self.context.i64_type().const_int(u64::MAX.into(), false);
                    let masked = self.builder.build_and(dst_reg_value, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                _ => {
                    panic!("unreachable")
                }
            },
            ebpf::BE => match insn.imm {
                16 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let mask = self.context.i64_type().const_int(u16::MAX.into(), false);
                    let masked = self.builder.build_and(dst_reg_value, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                32 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let mask = self.context.i64_type().const_int(u32::MAX.into(), false);
                    let masked = self.builder.build_and(dst_reg_value, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                64 => {
                    let dst_reg_value =
                        self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                    let bswap_intrinsic = Intrinsic::find("llvm.bswap").unwrap();
                    let bswap_function = bswap_intrinsic
                        .get_declaration(&self.module, &[self.context.i64_type().into()])
                        .unwrap();
                    let swapped = self
                        .builder
                        .build_call(bswap_function, &[dst_reg_value.into()], "")
                        .try_as_basic_value()
                        .unwrap_left()
                        .into_int_value();
                    let mask = self.context.i64_type().const_int(u64::MAX.into(), false);
                    let masked = self.builder.build_and(swapped, mask, "");
                    self.translate_write_ebpf_register(insn.dst, masked, per_function_env)?;
                }
                _ => {
                    panic!("unreachable")
                }
            },
            // BPF_ALU64 class
            ebpf::ADD64_IMM
            | ebpf::SUB64_IMM
            | ebpf::MUL64_IMM
            | ebpf::DIV64_IMM
            | ebpf::SDIV64_IMM
            | ebpf::MOD64_IMM
            | ebpf::OR64_IMM
            | ebpf::AND64_IMM
            | ebpf::LSH64_IMM
            | ebpf::RSH64_IMM
            | ebpf::XOR64_IMM
            | ebpf::ARSH64_IMM => {
                self.translate_instruction_alu64_imm(insn, per_function_env)?;
            }
            ebpf::ADD64_REG
            | ebpf::SUB64_REG
            | ebpf::MUL64_REG
            | ebpf::DIV64_REG
            | ebpf::SDIV64_REG
            | ebpf::MOD64_REG
            | ebpf::OR64_REG
            | ebpf::AND64_REG
            | ebpf::LSH64_REG
            | ebpf::RSH64_REG
            | ebpf::XOR64_REG
            | ebpf::ARSH64_REG => {
                self.translate_instruction_alu64_reg(insn, per_function_env)?;
            }
            ebpf::NEG64 => {
                let value = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                let negated = self.builder.build_int_neg(value, "");
                self.translate_write_ebpf_register(insn.dst, negated, per_function_env)?;
            }
            ebpf::MOV64_IMM => {
                let imm_value = self.context.i64_type().const_int(insn.imm as u64, true);
                self.translate_write_ebpf_register(insn.dst, imm_value, per_function_env)?;
            }
            ebpf::MOV64_REG => {
                let src_reg_value =
                    self.translate_read_ebpf_register(insn.src, per_function_env)?;
                self.translate_write_ebpf_register(insn.dst, src_reg_value, per_function_env)?;
            }
            // BPF_JMP class
            ebpf::JA => return Ok(NextTranslationTask::Jmp { target_pc }),
            ebpf::JEQ_IMM
            | ebpf::JGT_IMM
            | ebpf::JGE_IMM
            | ebpf::JLT_IMM
            | ebpf::JLE_IMM
            | ebpf::JNE_IMM
            | ebpf::JSGT_IMM
            | ebpf::JSGE_IMM
            | ebpf::JSLT_IMM
            | ebpf::JSLE_IMM => {
                return self.translate_instruction_jump_imm(
                    insn,
                    target_pc,
                    pc + 1,
                    per_function_env,
                );
            }
            ebpf::JEQ_REG
            | ebpf::JGT_REG
            | ebpf::JGE_REG
            | ebpf::JLT_REG
            | ebpf::JLE_REG
            | ebpf::JNE_REG
            | ebpf::JSGT_REG
            | ebpf::JSGE_REG
            | ebpf::JSLT_REG
            | ebpf::JSLE_REG => {
                return self.translate_instruction_jump_reg(
                    insn,
                    target_pc,
                    pc + 1,
                    per_function_env,
                );
            }
            ebpf::JSET_IMM => {
                let lhs = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                let rhs = self.context.i64_type().const_int(insn.imm as u64, true);
                let out = self.builder.build_and(lhs, rhs, "jset_imm.0");
                let predicate = self.builder.build_int_compare(
                    IntPredicate::NE,
                    out,
                    self.context.i64_type().const_zero(),
                    "jset_imm.1",
                );
                return Ok(NextTranslationTask::JmpCond {
                    predicate,
                    target_if: target_pc,
                    target_else: pc + 1,
                });
            }
            ebpf::JSET_REG => {
                let lhs = self.translate_read_ebpf_register(insn.dst, per_function_env)?;
                let rhs = self.translate_read_ebpf_register(insn.src, per_function_env)?;
                let out = self.builder.build_and(lhs, rhs, "jset_reg.0");
                let predicate = self.builder.build_int_compare(
                    IntPredicate::NE,
                    out,
                    self.context.i64_type().const_zero(),
                    "jset_reg.1",
                );
                return Ok(NextTranslationTask::JmpCond {
                    predicate,
                    target_if: target_pc,
                    target_else: pc + 1,
                });
            }
            ebpf::CALL_IMM => {
                let func_hash = insn.imm as u32;
                let function = if let Some(func) = self.syscall_map.get(&func_hash) {
                    *func
                } else if let Some(func) = self.function_map_by_hash.get(&func_hash) {
                    *func
                } else {
                    return Err(EbpfError::UnsupportedInstruction(pc));
                };
                self.builder.build_call(function, &[], "");
            }
            ebpf::CALL_REG => {
                let function_ty = self.context.i64_type().fn_type(&[], false);
                let function = self.module.add_function(
                    &format!("regcall_{}", pc),
                    function_ty,
                    Some(inkwell::module::Linkage::ExternalWeak),
                );
                self.builder.build_call(function, &[], "");
            }
            ebpf::EXIT => return Ok(NextTranslationTask::Exit),
            _ => {
                println!("unsupported opcode {:b} {:b}", insn.opc, ebpf::MOV32_REG);
                return Err(EbpfError::UnsupportedInstruction(
                    pc + ebpf::ELF_INSN_DUMP_OFFSET,
                ));
            }
        }
        pc += 1;
        Ok(NextTranslationTask::NextPc { target_pc: pc })
    }

    fn translate_basic_block(
        &self,
        analysis: &Analysis,
        mut pc: usize,
        per_function_env: &mut PerFunctionEnv<'ctx>,
    ) -> Result<BasicBlock<'ctx>, EbpfError> {
        if let Some(block) = per_function_env.basic_block_map.get(&pc) {
            return Ok(*block);
        }
        let block = self
            .context
            .append_basic_block(per_function_env.current_function, "");
        self.builder.position_at_end(block);
        per_function_env.basic_block_map.insert(pc, block);

        while pc <= analysis.instructions.len() {
            let res = self.translate_instruction(analysis, pc, per_function_env)?;
            match res {
                NextTranslationTask::NextPc { target_pc } => {
                    pc = target_pc;
                }
                NextTranslationTask::Jmp { target_pc } => {
                    let jump_block =
                        self.translate_basic_block(analysis, target_pc, per_function_env)?;
                    self.builder.position_at_end(block);
                    self.builder.build_unconditional_branch(jump_block);
                    return Ok(block);
                }
                NextTranslationTask::JmpCond {
                    predicate,
                    target_if,
                    target_else,
                } => {
                    let if_block =
                        self.translate_basic_block(analysis, target_if, per_function_env)?;
                    let else_block =
                        self.translate_basic_block(analysis, target_else, per_function_env)?;
                    self.builder.position_at_end(block);
                    self.builder
                        .build_conditional_branch(predicate, if_block, else_block);
                    return Ok(block);
                }
                NextTranslationTask::Exit => {
                    self.builder.build_return(None);
                    return Ok(block);
                }
            }
        }
        self.builder.build_return(None);
        Ok(block)
    }

    fn translate_function(
        &self,
        analysis: &Analysis,
        pc: usize,
        function: FunctionValue<'ctx>,
    ) -> Result<(), EbpfError> {
        let first_block = self.context.append_basic_block(function, "");
        self.builder.position_at_end(first_block);

        let basic_block_map = HashMap::new();
        // first block is not added to basic_block_map, because logically it has the same pc as the second block

        // populate register_map
        let int64_type = self.context.i64_type();
        let mut register_map = HashMap::new();
        for i in 0..11 {
            let alloca_ptr = self
                .builder
                .build_alloca(int64_type, &format!("ebpf_register{}", i));
            register_map.insert(i, alloca_ptr);
        }

        let mut per_function_env = PerFunctionEnv {
            current_function: function,
            register_map,
            basic_block_map,
        };

        // begin compilation
        let second_block = self.translate_basic_block(analysis, pc, &mut per_function_env)?;
        self.builder.position_at_end(first_block);
        self.builder.build_unconditional_branch(second_block);

        Ok(())
    }

    fn compile<C: ContextObject>(&mut self, executable: &Executable<C>) -> Result<(), EbpfError> {
        let analysis = Analysis::from_executable(executable)?;
        // add internal functions
        for (pc, (key, name)) in analysis.functions.iter() {
            let function_ty = self.context.i64_type().fn_type(&[], false);
            let function = self.module.add_function(name, function_ty, None);
            self.function_map_by_pc.insert(*pc, function);
            self.function_map_by_hash.insert(*key, function);
        }
        // add syscall functions
        for (syscall_hash, (syscall_name, _)) in analysis.executable.get_loader().iter_functions() {
            let function_ty = self.context.i64_type().fn_type(&[], false);
            let function = self.module.add_function(
                syscall_name,
                function_ty,
                Some(inkwell::module::Linkage::ExternalWeak),
            );
            self.syscall_map.insert(*syscall_hash, function);
        }
        for (&pc, &function) in self.function_map_by_pc.iter() {
            self.translate_function(&analysis, pc, function)?;
        }
        Ok(())
    }
}

/// Compiles eBPF code to .so bytes
pub fn jit_compile_llvm<C: ContextObject>(
    executable: &Executable<C>,
) -> Result<Vec<u8>, EbpfError> {
    Target::initialize_x86(&InitializationConfig::default());
    let target = Target::from_name("x86-64").expect("x86-64 unsupported");
    let target_machine = target
        .create_target_machine(
            &TargetTriple::create("x86_64-pc-linux-gnu"),
            "x86-64",
            "",
            OptimizationLevel::Default,
            RelocMode::PIC,
            CodeModel::Default,
        )
        .expect("Failed to initialize target machine");
    let context = Context::create();
    let mut jit = LLVMJitCompiler::new(&context).expect("Failed to initialize IRgen");
    jit.compile(executable)
        .expect("Failed to  generate LLVM IR");
    let machine_code = target_machine
        .write_to_memory_buffer(&jit.module, FileType::Object)
        .expect("Failed to generate machine code")
        .as_slice()
        .to_vec();
    Ok(machine_code)
}
