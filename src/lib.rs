//! this is a crate which allows encoding, decoding and working with x86 instructions in a very convenient and user-friendly way.
//!
//! it uses the `Zydis` library under the hood, but provides user-friendly wrappers around `Zydis`' interfaces to make it
//! easier to work with.
//!
//! # Example
//! ```
//! let state = rydis::RydisState::new(MachineMode::Long64, StackWidth::Width64)?;
//!
//! // encode an instruction
//! let encoded = state.encode(Instruction {
//!     prefixes: Prefixes::empty(),
//!     mnemonic: Mnemonic::XCHG,
//!     operands: [Operand::Reg(Register::RAX), Operand::Reg(Register::RBX)]
//!         .into_iter()
//!         .collect(),
//! })?;
//!
//! // decode it
//! let decoded_instruction = state.decode_one(encoded.as_slice())?;
//!
//! // modify it
//! let mut modified_instruction = decoded_instruction.to_instruction();
//! modified_instruction.operands[1] = Operand::Mem(MemOperand {
//!     base: Some(Register::RBP),
//!     index: None,
//!     displacement: 0x1234,
//!     size: decoded_instruction.operand_width,
//!     segment_register_override: None,
//! });
//!
//! // format it
//! println!(
//!     "modified insn: {}",
//!     modified_instruction.format(&state, FormatStyle::Intel, Some(0x123400))?
//! );
//!
//! // re-encode the modified instruction
//! let re_encoded = state.encode(modified_instruction)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

mod enums;

use core::num::NonZeroU8;

use arrayvec::{ArrayString, ArrayVec};
use num_enum::FromPrimitive;
use thiserror_no_std::Error;
use zydis_sys::*;

pub use enums::*;

/// the maximum length of an instruction, in bytes.
pub const MAX_INSTRUCTION_LEN: usize = ZYDIS_MAX_INSTRUCTION_LENGTH as usize;

/// the maximum length of a formatted instruction string, in bytes.
pub const MAX_FORMATTED_INSTRUCTION_LEN: usize = 256;

/// the maximum amount of operands of a single instruction.
pub const MAX_OPERANDS_AMOUNT: usize = ZYDIS_MAX_OPERAND_COUNT as usize;

/// convert a zyan status code returned from zydis functions to a rust result.
fn zyan_check(status: ZyanStatus) -> Result<()> {
    let bitfield = ZyanStatusBitfield::from(status);
    if bitfield.is_error() {
        if bitfield.module() == ZYAN_MODULE_ZYDIS {
            Err(Error::ZydisError(ZydisError::from_primitive(
                bitfield.code(),
            )))
        } else {
            Err(Error::UnknownZyanError {
                module: bitfield.module(),
                code: bitfield.code(),
            })
        }
    } else {
        Ok(())
    }
}

/// a structure which encapsulates information required for encoding/decoding instructions.
#[derive(Debug, Clone, Copy)]
pub struct RydisState {
    machine_mode: MachineMode,
    decoder: ZydisDecoder,
}
impl RydisState {
    /// creates a new state with the given arguments.
    pub fn new(machine_mode: MachineMode, stack_width: StackWidth) -> Result<Self> {
        let mut decoder = ZydisDecoder::default();
        zyan_check(unsafe {
            ZydisDecoderInit(&mut decoder, machine_mode.to_raw(), stack_width.to_raw())
        })?;
        Ok(Self {
            machine_mode,
            decoder,
        })
    }

    /// encodes the given instruction.
    pub fn encode(&self, mut instruction: Instruction) -> Result<EncodedInstructionBuf> {
        instruction.fix_for_encoding();
        let req = instruction.to_zydis_encoder_request(self.machine_mode.to_raw());
        let mut insn_buf = EncodedInstructionBuf::new();
        let mut insn_len = MAX_INSTRUCTION_LEN as u64;
        zyan_check(unsafe {
            ZydisEncoderEncodeInstruction(&req, insn_buf.as_mut_ptr().cast(), &mut insn_len)
        })?;
        unsafe {
            insn_buf.set_len(insn_len as usize);
        }
        Ok(insn_buf)
    }

    /// decodes a single instruction from the given buffer.
    pub fn decode_one(&self, buf: &[u8]) -> Result<DecodedInstruction> {
        let mut raw_instruction = ZydisDecodedInstruction::default();
        let mut operands = [ZydisDecodedOperand::default(); MAX_OPERANDS_AMOUNT];
        zyan_check(unsafe {
            ZydisDecoderDecodeFull(
                &self.decoder,
                buf.as_ptr().cast(),
                buf.len() as u64,
                &mut raw_instruction,
                operands.as_mut_ptr(),
            )
        })?;

        let mut instruction = DecodedInstruction {
            prefixes: Prefixes::from_bits_truncate(raw_instruction.attributes),
            mnemonic: Mnemonic::from_raw(raw_instruction.mnemonic)?,
            // the operands will be updated later
            operands: ArrayVec::new(),
            // the invisible operands will be updated later
            invisible_operands: ArrayVec::new(),
            operand_width: raw_instruction.operand_width / 8,
            address_width: raw_instruction.address_width / 8,
            accessed_flags: unsafe { &*raw_instruction.cpu_flags },
            len: raw_instruction.length as usize,
        };

        // find the segment register override
        let mut segment_register_override = None;
        for (segment_register, attrib) in [
            (SegmentRegister::CS, ZYDIS_ATTRIB_HAS_SEGMENT_CS),
            (SegmentRegister::SS, ZYDIS_ATTRIB_HAS_SEGMENT_SS),
            (SegmentRegister::DS, ZYDIS_ATTRIB_HAS_SEGMENT_DS),
            (SegmentRegister::ES, ZYDIS_ATTRIB_HAS_SEGMENT_ES),
            (SegmentRegister::FS, ZYDIS_ATTRIB_HAS_SEGMENT_FS),
            (SegmentRegister::GS, ZYDIS_ATTRIB_HAS_SEGMENT_GS),
        ] {
            if raw_instruction.attributes & attrib != 0 {
                if segment_register_override.is_some() {
                    return Err(Error::MultipleSegmentOverrideAttributes(
                        buf[..raw_instruction.length as usize].try_into().unwrap(),
                    ));
                }
                segment_register_override = Some(segment_register);
            }
        }

        for i in 0..raw_instruction.operand_count {
            let raw_operand = &operands[i as usize];
            let operand = unsafe {
                DecodedOperand {
                    operand: match raw_operand.type_ {
                        ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER => {
                            Operand::Reg(Register::from_raw_disallow_none(
                                raw_operand.__bindgen_anon_1.reg.value,
                            )?)
                        }
                        ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY => Operand::Mem(MemOperand {
                            base: Register::from_raw(raw_operand.__bindgen_anon_1.mem.base),
                            index: match NonZeroU8::new(raw_operand.__bindgen_anon_1.mem.scale) {
                                Some(scale) => Some(MemOperandIndex {
                                    reg: Register::from_raw(raw_operand.__bindgen_anon_1.mem.index)
                                        .unwrap_or(Register::RAX),
                                    scale,
                                }),
                                None => None,
                            },
                            displacement: raw_operand.__bindgen_anon_1.mem.disp.value,
                            size: raw_instruction.operand_width / 8,
                            segment_register_override,
                        }),
                        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => Operand::Imm({
                            let size_mask = if raw_instruction.operand_width == 64 {
                                u64::MAX
                            } else {
                                (1 << raw_instruction.operand_width) - 1
                            };
                            raw_operand.__bindgen_anon_1.imm.value.u & size_mask
                        }),
                        ZydisOperandType::ZYDIS_OPERAND_TYPE_POINTER => Operand::Ptr(PtrOperand {
                            segment: raw_operand.__bindgen_anon_1.ptr.segment,
                            offset: raw_operand.__bindgen_anon_1.ptr.offset,
                        }),
                        ty => return Err(Error::InvalidOperandType(ty.0)),
                    },
                    actions: OperandActions::from_bits_truncate(raw_operand.actions as u32),
                }
            };
            if raw_operand.visibility == ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_HIDDEN {
                instruction.invisible_operands.push(operand);
            } else {
                instruction.operands.push(operand);
            }
        }
        Ok(instruction)
    }

    /// returns an iterator which decodes instructions from the given buffer.
    pub fn decode_iter<'a>(&self, buf: &'a [u8]) -> DecodeIter<'a> {
        DecodeIter {
            buf,
            state: self.clone(),
            cur_index: 0,
        }
    }
}

/// an iterator which decodes instructions from a buffer.
pub struct DecodeIter<'a> {
    buf: &'a [u8],
    cur_index: usize,
    state: RydisState,
}
impl<'a> Iterator for DecodeIter<'a> {
    type Item = Result<DecodedIterInstruction<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur_index >= self.buf.len() {
            return None;
        }
        match self.state.decode_one(&self.buf[self.cur_index..]) {
            Ok(instruction) => {
                let instruction_bytes = &self.buf[self.cur_index..][..instruction.len];
                let instruction_index = self.cur_index;
                self.cur_index += instruction.len;
                Some(Ok(DecodedIterInstruction {
                    bytes: instruction_bytes,
                    instruction,
                    index_in_buffer: instruction_index,
                }))
            }
            Err(err) => Some(Err(err)),
        }
    }
}

/// a buffer for an encoded instruction.
pub type EncodedInstructionBuf = ArrayVec<u8, MAX_INSTRUCTION_LEN>;

bitflags::bitflags! {
    /// the prefixes of an instruction.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub struct Prefixes : u64 {
        const LOCK = ZYDIS_ATTRIB_HAS_LOCK as u64;
        const REP = ZYDIS_ATTRIB_HAS_REP as u64;
        const REPE = ZYDIS_ATTRIB_HAS_REPE as u64;
        const REPNE = ZYDIS_ATTRIB_HAS_REPNE as u64;
        const BND = ZYDIS_ATTRIB_HAS_BND as u64;
        const XACQUIRE = ZYDIS_ATTRIB_HAS_XACQUIRE as u64;
        const XRELEASE = ZYDIS_ATTRIB_HAS_XRELEASE as u64;
        const NOTRACK = ZYDIS_ATTRIB_HAS_NOTRACK as u64;
    }
}

/// information about the flags accessed by an instruction.
pub type AccessedFlags = ZydisAccessedFlags;

/// a mask of the flags accessed in some way by some instruction.
pub type AccessedFlagsMask = ZydisAccessedFlagsMask;

bitflags::bitflags! {
    /// the actions that an operand is used for by an instruction.
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub struct OperandActions : u32 {
        /// the operand is read by the instruction.
        const READ = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_READ.0;
        /// the operand is written by the instruction (must write).
        const WRITE = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_WRITE.0;
        /// the operand is conditionally read by the instruction.
        const CONDREAD = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_CONDREAD.0;
        /// the operand is conditionally written by the instruction (may write).
        const CONDWRITE = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_CONDWRITE.0;
        /// mask combining all reading access flags.
        const READ_MASK = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_MASK_READ.0;
        /// mask combining all writing access flags.
        const WRITE_MASK = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_MASK_WRITE.0;
    }
}

/// information about a decoded instruction using the iterator decoder.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodedIterInstruction<'a> {
    /// the bytes of the instruction
    pub bytes: &'a [u8],

    /// the actual decoded instruction.
    pub instruction: DecodedInstruction,

    /// the index of the first byte of this instruction in the decoded buffer.
    pub index_in_buffer: usize,
}

/// an array of operands of an instruction.
pub type InstructionOperands = ArrayVec<Operand, MAX_OPERANDS_AMOUNT>;

/// an array of operands of a decoded instruction.
pub type DecodedInstructionOperands = ArrayVec<DecodedOperand, MAX_OPERANDS_AMOUNT>;

/// information about a decoded instruction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodedInstruction {
    /// the instruction's prefixes.
    pub prefixes: Prefixes,

    /// the instruction's mnemonic.
    pub mnemonic: Mnemonic,

    /// the instruction's explicit operands, which are the operands that are specified in the instruction's textual representation.
    pub operands: DecodedInstructionOperands,

    /// the invisible operands of this instruction, which are operands that are used even though they are not directly specified
    /// in the instruction's textual representation.
    pub invisible_operands: DecodedInstructionOperands,

    /// the width of the instruction's operands, in bytes
    pub operand_width: u8,

    /// the address width of the instruction, in bytes
    pub address_width: u8,

    /// the flags accessed by the instruction.
    pub accessed_flags: &'static AccessedFlags,

    /// the length of the instruction, in bytes.
    pub len: usize,
}

impl DecodedInstruction {
    /// converts this decoded instruction to an [`Instruction`].
    pub fn to_instruction(&self) -> Instruction {
        Instruction {
            prefixes: self.prefixes,
            mnemonic: self.mnemonic,
            operands: self
                .operands
                .iter()
                .map(|decoded_operand| decoded_operand.operand.clone())
                .collect(),
        }
    }
}

/// information about a decoded operand.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct DecodedOperand {
    /// the actual operand.
    pub operand: Operand,

    /// the actions performed on the operand by the instruction.
    pub actions: OperandActions,
}

/// an instruction.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Instruction {
    /// the instruction's prefixes.
    pub prefixes: Prefixes,

    /// the instruction's mnemonic.
    pub mnemonic: Mnemonic,

    /// the instruction's explicit operands, which are the operands that are specified in the instruction's textual representation.
    pub operands: InstructionOperands,
}
impl Instruction {
    /// returns the memory operand of this instruction, if any.
    pub fn memory_operand(&self) -> Option<&MemOperand> {
        self.operands.iter().find_map(|op| match op {
            Operand::Mem(mem_operand) => Some(mem_operand),
            _ => None,
        })
    }

    fn get_zydis_operand_size_hint(&self) -> ZydisOperandSizeHint {
        match self.memory_operand() {
            Some(mem_operand) => match mem_operand.size {
                1 => ZydisOperandSizeHint::ZYDIS_OPERAND_SIZE_HINT_8,
                2 => ZydisOperandSizeHint::ZYDIS_OPERAND_SIZE_HINT_16,
                4 => ZydisOperandSizeHint::ZYDIS_OPERAND_SIZE_HINT_32,
                8 => ZydisOperandSizeHint::ZYDIS_OPERAND_SIZE_HINT_64,
                _ => ZydisOperandSizeHint::ZYDIS_OPERAND_SIZE_HINT_NONE,
            },
            _ => ZydisOperandSizeHint_::ZYDIS_OPERAND_SIZE_HINT_NONE,
        }
    }

    fn get_zydis_segment_register_prefix(&self) -> u64 {
        match self.memory_operand() {
            Some(MemOperand {
                segment_register_override: Some(segment_reg),
                ..
            }) => match segment_reg {
                SegmentRegister::CS => ZYDIS_ATTRIB_HAS_SEGMENT_CS,
                SegmentRegister::SS => ZYDIS_ATTRIB_HAS_SEGMENT_SS,
                SegmentRegister::DS => ZYDIS_ATTRIB_HAS_SEGMENT_DS,
                SegmentRegister::ES => ZYDIS_ATTRIB_HAS_SEGMENT_ES,
                SegmentRegister::FS => ZYDIS_ATTRIB_HAS_SEGMENT_FS,
                SegmentRegister::GS => ZYDIS_ATTRIB_HAS_SEGMENT_GS,
            },
            _ => 0,
        }
    }

    fn get_zydis_prefixes(&self) -> u64 {
        self.prefixes.bits() | self.get_zydis_segment_register_prefix()
    }

    /// there are some special edge cases which must be fixed in the instruction before converting it to an encoder request.
    fn fix_for_encoding(&mut self) {
        if self.mnemonic == Mnemonic::XCHG {
            // in xchg instructions, if one of the operands is a memory operand, it must be the first operand.
            for i in 1..self.operands.len() {
                if matches!(self.operands[i], Operand::Mem(_)) {
                    self.operands.swap(0, i);
                }
            }
        }
    }

    /// converts this instruction to a zydis encoder request.
    /// it is recommended to first call the [`fix_for_encoding`] method, otherwise the generated request may be broken.
    fn to_zydis_encoder_request(&self, machine_mode: ZydisMachineMode) -> ZydisEncoderRequest {
        let mut operands = [ZydisEncoderOperand::default(); 5];
        for (operand, zydis_operand) in self.operands.iter().zip(operands.iter_mut()) {
            *zydis_operand = operand.to_zydis_encoder_operand();
        }
        ZydisEncoderRequest {
            machine_mode,
            mnemonic: self.mnemonic.to_raw(),
            prefixes: self.get_zydis_prefixes(),
            branch_type: ZydisBranchType::ZYDIS_BRANCH_TYPE_NONE,
            operand_size_hint: self.get_zydis_operand_size_hint(),
            operand_count: self.operands.len() as u8,
            operands,
            allowed_encodings: ZydisEncodableEncoding::ZYDIS_ENCODABLE_ENCODING_LEGACY,
            ..Default::default()
        }
    }

    /// formats this instruction into a string.
    pub fn format(
        &self,
        state: &RydisState,
        style: FormatStyle,
        runtime_address: Option<u64>,
    ) -> Result<FormattedInstruction> {
        let mut formatter = ZydisFormatter::default();
        zyan_check(unsafe { ZydisFormatterInit(&mut formatter, style.to_raw()) })?;

        // to format an instruction using the zydis API we need a decoded instruction, so generate one by encoding and decoding
        // this instruction.
        let encoded = state.encode(self.clone())?;
        let mut decoded_instruction = ZydisDecodedInstruction::default();
        let mut decoded_operands = [ZydisDecodedOperand::default(); MAX_OPERANDS_AMOUNT];
        zyan_check(unsafe {
            ZydisDecoderDecodeFull(
                &state.decoder,
                encoded.as_ptr().cast(),
                encoded.len() as u64,
                &mut decoded_instruction,
                decoded_operands.as_mut_ptr(),
            )
        })?;

        let mut result = FormattedInstruction::new();
        zyan_check(unsafe {
            ZydisFormatterFormatInstruction(
                &formatter,
                &decoded_instruction,
                decoded_operands.as_ptr(),
                decoded_instruction.operand_count_visible,
                result.as_bytes_mut().as_mut_ptr().cast(),
                MAX_FORMATTED_INSTRUCTION_LEN as u64,
                runtime_address.unwrap_or(u64::MAX),
                core::ptr::null_mut(),
            )
        })?;

        // calculate the length by finding the null byte
        let len = unsafe {
            core::slice::from_raw_parts(result.as_bytes().as_ptr(), MAX_FORMATTED_INSTRUCTION_LEN)
        }
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::FormattedInstructionTooLong(self.clone()))?;

        unsafe { result.set_len(len) }

        Ok(result)
    }
}

/// a formatted instruction string.
pub type FormattedInstruction = ArrayString<MAX_FORMATTED_INSTRUCTION_LEN>;

/// an operand.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Operand {
    /// an immediate operand.
    Imm(u64),
    /// a memory operand, for example `[rbp+2*rsi+0x35]`.
    Mem(MemOperand),
    /// a pointer operand, for example `0x10:0x1234`.
    Ptr(PtrOperand),
    /// a register operand.
    Reg(Register),
}
impl Operand {
    pub fn as_imm(&self) -> Option<u64> {
        match self {
            Self::Imm(x) => Some(*x),
            _ => None,
        }
    }
    pub fn as_imm_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Imm(x) => Some(x),
            _ => None,
        }
    }
    pub fn as_mem(&self) -> Option<&MemOperand> {
        match self {
            Self::Mem(x) => Some(x),
            _ => None,
        }
    }
    pub fn as_mem_mut(&mut self) -> Option<&mut MemOperand> {
        match self {
            Self::Mem(x) => Some(x),
            _ => None,
        }
    }
    pub fn as_ptr(&self) -> Option<&PtrOperand> {
        match self {
            Self::Ptr(x) => Some(x),
            _ => None,
        }
    }
    pub fn as_ptr_mut(&mut self) -> Option<&mut PtrOperand> {
        match self {
            Self::Ptr(x) => Some(x),
            _ => None,
        }
    }
    pub fn as_reg(&self) -> Option<Register> {
        match self {
            Self::Reg(x) => Some(*x),
            _ => None,
        }
    }
    pub fn as_reg_mut(&mut self) -> Option<&mut Register> {
        match self {
            Self::Reg(x) => Some(x),
            _ => None,
        }
    }
    fn to_zydis_encoder_operand(&self) -> ZydisEncoderOperand {
        match self {
            Operand::Imm(imm) => ZydisEncoderOperand_ {
                type_: ZydisOperandType_::ZYDIS_OPERAND_TYPE_IMMEDIATE,
                imm: ZydisEncoderOperand__ZydisEncoderOperandImm_ { u: *imm },
                ..Default::default()
            },
            Operand::Mem(mem) => ZydisEncoderOperand_ {
                type_: ZydisOperandType_::ZYDIS_OPERAND_TYPE_MEMORY,
                mem: ZydisEncoderOperand__ZydisEncoderOperandMem_ {
                    base: mem
                        .base
                        .map(|base| base.to_raw())
                        .unwrap_or(ZydisRegister::ZYDIS_REGISTER_NONE),
                    index: match &mem.index {
                        Some(index) => index.reg.to_raw(),
                        None => ZydisRegister_::ZYDIS_REGISTER_NONE,
                    },
                    scale: mem
                        .index
                        .as_ref()
                        .map(|index| index.scale.get())
                        .unwrap_or(0),
                    displacement: mem.displacement,
                    size: mem.size as u16,
                },
                ..Default::default()
            },
            Operand::Ptr(ptr) => ZydisEncoderOperand_ {
                type_: ZydisOperandType_::ZYDIS_OPERAND_TYPE_POINTER,
                ptr: ZydisEncoderOperand__ZydisEncoderOperandPtr_ {
                    segment: ptr.segment,
                    offset: ptr.offset,
                },
                ..Default::default()
            },
            Operand::Reg(reg) => ZydisEncoderOperand_ {
                type_: ZydisOperandType_::ZYDIS_OPERAND_TYPE_REGISTER,
                reg: ZydisEncoderOperand__ZydisEncoderOperandReg_ {
                    value: reg.to_raw(),
                    is4: 0,
                },
                ..Default::default()
            },
        }
    }
}

/// a memory operand, for example `[rbp+2*rsi+0x35]`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct MemOperand {
    /// the base register.
    pub base: Option<Register>,
    /// the index.
    pub index: Option<MemOperandIndex>,
    /// the displacement value.
    pub displacement: i64,
    /// size of this operand in bytes.
    pub size: u8,
    /// the segment register override.
    pub segment_register_override: Option<SegmentRegister>,
}

/// the index of a memory operand, for example the `2*rsi` part in `[rbp+2*rsi+0x35]`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct MemOperandIndex {
    /// the index register.
    pub reg: Register,
    /// the scale factor.
    pub scale: NonZeroU8,
}

/// A pointer operand, for example `0x10:0x1234`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PtrOperand {
    /// the segment value.
    pub segment: u16,
    /// the offset value.
    pub offset: u32,
}

impl Register {
    fn from_raw(raw: ZydisRegister) -> Option<Self> {
        if raw == ZydisRegister::ZYDIS_REGISTER_NONE {
            None
        } else {
            Some(unsafe { core::mem::transmute(raw) })
        }
    }
    fn from_raw_disallow_none(raw: ZydisRegister) -> Result<Self> {
        Self::from_raw(raw).ok_or(Error::UnexpectedNoneRegister)
    }
    fn to_raw(&self) -> ZydisRegister {
        ZydisRegister_(*self as u32)
    }

    /// tries to convert this register to a segment register, returning an error if it is not a segment register.
    pub fn to_segment_register(&self) -> Result<SegmentRegister> {
        SegmentRegister::from_register(*self)
    }

    /// returns the width of this register, in bytes.
    pub fn width(&self, state: &RydisState) -> u8 {
        unsafe { ZydisRegisterGetWidth(state.machine_mode.to_raw(), self.to_raw()) as u8 / 8 }
    }

    /// returns the largest enclosing register of this register, or an error if the register is invalid for the active machine-mode.
    pub fn largest_enclosing(&self, state: &RydisState) -> Result<Register> {
        Register::from_raw(unsafe {
            ZydisRegisterGetLargestEnclosing(state.machine_mode.to_raw(), self.to_raw())
        })
        .ok_or(Error::RegisterNotValidInMachineMode {
            register: *self,
            machine_mode: state.machine_mode,
        })
    }

    /// returns the name of this register when written in assembly code.
    pub fn assembly_name(&self) -> &'static str {
        unsafe { zydis_short_str_to_str(ZydisRegisterGetStringWrapped(self.to_raw())) }
    }
}

impl Mnemonic {
    fn from_raw(raw: ZydisMnemonic) -> Result<Self> {
        if raw == ZydisMnemonic::ZYDIS_MNEMONIC_INVALID {
            Err(Error::InvalidMnemonic)
        } else {
            Ok(unsafe { core::mem::transmute(raw) })
        }
    }
    fn to_raw(&self) -> ZydisMnemonic {
        ZydisMnemonic_(*self as u32)
    }

    /// returns the name of this mnemonic when written in assembly code.
    pub fn assembly_name(&self) -> &'static str {
        unsafe { zydis_short_str_to_str(ZydisMnemonicGetStringWrapped(self.to_raw())) }
    }
}

impl MachineMode {
    fn to_raw(&self) -> ZydisMachineMode {
        ZydisMachineMode_(*self as u32)
    }
}

impl StackWidth {
    fn to_raw(&self) -> ZydisStackWidth {
        ZydisStackWidth_(*self as u32)
    }
}

impl FormatStyle {
    fn to_raw(&self) -> ZydisFormatterStyle {
        ZydisFormatterStyle_(*self as u32)
    }
}

/// converts a zydis short string to a rust string
unsafe fn zydis_short_str_to_str(short_str_ptr: *const ZydisShortString) -> &'static str {
    if short_str_ptr.is_null() {
        return "<invalid>";
    }
    let short_str = &*short_str_ptr;
    let bytes = core::slice::from_raw_parts(short_str.data.cast::<u8>(), short_str.size as usize);
    core::str::from_utf8(bytes).unwrap_or("<non utf-8>")
}

/// a segment register.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum SegmentRegister {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}
impl SegmentRegister {
    /// tries to convert the given register to a segment register, returning an error if it is not a segment register.
    pub fn from_register(reg: Register) -> Result<SegmentRegister> {
        match reg {
            Register::CS => Ok(SegmentRegister::CS),
            Register::SS => Ok(SegmentRegister::SS),
            Register::DS => Ok(SegmentRegister::DS),
            Register::ES => Ok(SegmentRegister::ES),
            Register::FS => Ok(SegmentRegister::FS),
            Register::GS => Ok(SegmentRegister::GS),
            _ => Err(Error::ExpectedSegmentRegister(reg)),
        }
    }
}

/// an error returned from the zydis library.
#[derive(Debug, Error, FromPrimitive)]
#[repr(u32)]
pub enum ZydisError {
    #[error("an attempt was made to read data from an input data-source that has no more data available")]
    EarlyEOF,

    #[error("a general error occured while decoding the current instruction, the instruction might be undefined")]
    GeneralDecodingError,

    #[error("the instruction exceeded the maximum length of 15 bytes")]
    InstructionTooLong,

    #[error("the instruction encoded an invalid register")]
    BadRegister,

    #[error(
        "a lock-prefix (F0) was found while decoding an instruction that does not support locking"
    )]
    IllegalLockPrefix,

    #[error(
        "a legacy-prefix (F2, F3, 66) was found while decoding a XOP/VEX/EVEX/MVEX instruction"
    )]
    IllegalLegacyPrefix,

    #[error("a rex-prefix was found while decoding a XOP/VEX/EVEX/MVEX instruction")]
    IllegalRexPrefix,

    #[error("an invalid opcode-map value was found while decoding a XOP/VEX/EVEX/MVEX-prefix")]
    InvalidOpcodeMap,

    #[error("an error occured while decoding the EVEX-prefix")]
    MalformedEvex,

    #[error("an error occured while decoding the MVEX-prefix")]
    MalformedMvex,

    #[error("an invalid write-mask was specified for an EVEX/MVEX instruction.")]
    InvalidMask,

    #[error("skipped token")]
    SkipToken,

    #[error("impossible instruction")]
    ImpossibleInstruction,

    #[num_enum(default)]
    #[error("unknown error")]
    Unknown,
}

/// the error type of this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("zydis error")]
    ZydisError(#[source] ZydisError),

    #[error("unknown zyan error, module 0x{module:x}, code 0x{code:x}")]
    UnknownZyanError { module: u32, code: u32 },

    #[error("a register value of `None` was used somewhere were it didn't make sense")]
    UnexpectedNoneRegister,

    #[error(
        "a non-segment register ({0:?}) was used somewhere where a segment register was expected"
    )]
    ExpectedSegmentRegister(Register),

    #[error("encountered an invalid operand type {0:x}")]
    InvalidOperandType(u32),

    #[error("encountered an invalid mnemonic value")]
    InvalidMnemonic,

    #[error("register {register:?} is not valid in machine mode {machine_mode:?}")]
    RegisterNotValidInMachineMode {
        register: Register,
        machine_mode: MachineMode,
    },

    #[error("formatted string is too long for instruction {0:?}")]
    FormattedInstructionTooLong(Instruction),

    #[error("instruction has multiple segment override attributes, code: {0:x?}")]
    MultipleSegmentOverrideAttributes(EncodedInstructionBuf),
}

/// the result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// a definition for the bitfield of a zyan status.
/// this provides us with convenient access to the different fields.
#[bitfield_struct::bitfield(u32)]
struct ZyanStatusBitfield {
    #[bits(20)]
    code: u32,

    #[bits(11)]
    module: u32,

    is_error: bool,
}
