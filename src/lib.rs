//! this is a crate which allows encoding, decoding and working with x86 instructions in a very convenient and user-friendly way.
//!
//! it uses the `Zydis` library under the hook, but provides user-friendly wrappers around `Zydis`' interfaces to make it
//! easier to work with.
//!
//! # Example
//! ```
//! let state = rydis::RydisState::new(
//!     MachineMode::ZYDIS_MACHINE_MODE_LONG_64,
//!     StackWidth::ZYDIS_STACK_WIDTH_64,
//! )?;
//!
//! // encode an instruction
//! let encoded = state.encode(Instruction {
//!     prefixes: Prefixes::empty(),
//!     mnemonic: Mnemonic::ZYDIS_MNEMONIC_XCHG,
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
//! // re-encode the modified instruction
//! let re_encoded = state.encode(modified_instruction)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

use core::num::NonZeroU8;

use arrayvec::ArrayVec;
use num_enum::{FromPrimitive, TryFromPrimitive};
use thiserror_no_std::Error;
use zydis_sys::*;

/// the maximum length of an instruction, in bytes.
pub const MAX_INSTRUCTION_LEN: usize = ZYDIS_MAX_INSTRUCTION_LENGTH as usize;

/// the maximum amount of operands of a single instruction.
pub const MAX_OPERANDS_AMOUNT: usize = ZYDIS_MAX_OPERAND_COUNT as usize;

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

/// the machine mode to decode instructions according to.
pub type MachineMode = ZydisMachineMode;

/// the stack width to decode instructions according to.
pub type StackWidth = ZydisStackWidth;

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
        zyan_check(unsafe { ZydisDecoderInit(&mut decoder, machine_mode, stack_width) })?;
        Ok(Self {
            machine_mode,
            decoder,
        })
    }

    /// encodes the given instruction.
    pub fn encode(&self, mut instruction: Instruction) -> Result<EncodedInstructionBuf> {
        instruction.fix_for_encoding();
        let req = instruction.to_zydis_encoder_request(self.machine_mode);
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

        // debug
        unsafe {
            let mut req = ZydisEncoderRequest::default();
            zyan_check(ZydisEncoderDecodedInstructionToEncoderRequest(
                &raw_instruction,
                operands.as_ptr(),
                raw_instruction.operand_count_visible,
                &mut req,
            ))?;
        }

        let mut instruction = DecodedInstruction {
            prefixes: Prefixes::from_bits_truncate(raw_instruction.attributes),
            mnemonic: raw_instruction.mnemonic,
            // the operands will be updated later
            operands: ArrayVec::new(),
            // the invisible operands will be updated later
            invisible_operands: ArrayVec::new(),
            operand_width: raw_instruction.operand_width / 8,
            address_width: raw_instruction.address_width / 8,
            accessed_flags: unsafe { &*raw_instruction.cpu_flags },
            len: raw_instruction.length,
        };
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
                            base: Register::from_raw(raw_operand.__bindgen_anon_1.mem.base)?,
                            index: match NonZeroU8::new(raw_operand.__bindgen_anon_1.mem.scale) {
                                Some(scale) => Some(MemOperandIndex {
                                    reg: Register::from_raw(
                                        raw_operand.__bindgen_anon_1.mem.index,
                                    )?
                                    .unwrap_or(Register::RAX),
                                    scale,
                                }),
                                None => None,
                            },
                            displacement: raw_operand.__bindgen_anon_1.mem.disp.value,
                            size: raw_instruction.operand_width / 8,
                            segment_register_override: match Register::from_raw(
                                raw_operand.__bindgen_anon_1.mem.segment,
                            )? {
                                Some(reg) => Some(SegmentRegister::from_register(reg)?),
                                None => None,
                            },
                        }),
                        ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE => {
                            Operand::Imm(raw_operand.__bindgen_anon_1.imm.value.u)
                        }
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
}

/// a buffer for an encoded instruction.
pub type EncodedInstructionBuf = ArrayVec<u8, MAX_INSTRUCTION_LEN>;

/// an instruction mnemonic.
pub type Mnemonic = ZydisMnemonic;

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
        /// The operand is read by the instruction.
        const READ = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_READ.0;
        /// The operand is written by the instruction (must write).
        const WRITE = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_WRITE.0;
        /// The operand is conditionally read by the instruction.
        const CONDREAD = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_CONDREAD.0;
        /// The operand is conditionally written by the instruction (may write).
        const CONDWRITE = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_CONDWRITE.0;
        /// Mask combining all reading access flags.
        const READ_MASK = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_MASK_READ.0;
        /// Mask combining all writing access flags.
        const WRITE_MASK = ZydisOperandAction_::ZYDIS_OPERAND_ACTION_MASK_WRITE.0;
    }
}

/// information about a decoded instruction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodedInstruction {
    /// the instruction's prefixes.
    pub prefixes: Prefixes,

    /// the instruction's mnemonic.
    pub mnemonic: Mnemonic,

    /// the instruction's explicit operands, which are the operands that are specified in the instruction's textual representation.
    pub operands: ArrayVec<DecodedOperand, MAX_OPERANDS_AMOUNT>,

    /// the invisible operands of this instruction, which are operands that are used even though they are not directly specified
    /// in the instruction's textual representation.
    pub invisible_operands: ArrayVec<DecodedOperand, MAX_OPERANDS_AMOUNT>,

    /// the width of the instruction's operands, in bytes
    pub operand_width: u8,

    /// the address width of the instruction, in bytes
    pub address_width: u8,

    /// the flags accessed by the instruction.
    pub accessed_flags: &'static AccessedFlags,

    /// the length of the instruction, in bytes.
    pub len: u8,
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
    pub operands: ArrayVec<Operand, MAX_OPERANDS_AMOUNT>,
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
        if self.mnemonic == Mnemonic::ZYDIS_MNEMONIC_XCHG {
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
            mnemonic: self.mnemonic,
            prefixes: self.get_zydis_prefixes(),
            branch_type: ZydisBranchType::ZYDIS_BRANCH_TYPE_NONE,
            operand_size_hint: self.get_zydis_operand_size_hint(),
            operand_count: self.operands.len() as u8,
            operands,
            allowed_encodings: ZydisEncodableEncoding::ZYDIS_ENCODABLE_ENCODING_LEGACY,
            ..Default::default()
        }
    }
}

/// an operand.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Operand {
    /// An immediate operand.
    Imm(u64),
    /// A memory operand, for example `[rbp+2*rsi+0x35]`.
    Mem(MemOperand),
    /// A pointer operand, for example `0x10:0x1234`.
    Ptr(PtrOperand),
    /// A register operand.
    Reg(Register),
}
impl Operand {
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

/// A memory operand, for example `[rbp+2*rsi+0x35]`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct MemOperand {
    /// The base register.
    pub base: Option<Register>,
    /// The index.
    pub index: Option<MemOperandIndex>,
    /// The displacement value.
    pub displacement: i64,
    /// Size of this operand in bytes.
    pub size: u8,
    /// The segment register override.
    pub segment_register_override: Option<SegmentRegister>,
}

/// the index of a memory operand, for example the `2*rsi` part in `[rbp+2*rsi+0x35]`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct MemOperandIndex {
    /// The index register.
    pub reg: Register,
    /// The scale factor.
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

/// A register.
#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy, Hash)]
#[repr(u32)]
pub enum Register {
    AL = 1,
    CL = 2,
    DL = 3,
    BL = 4,
    AH = 5,
    CH = 6,
    DH = 7,
    BH = 8,
    SPL = 9,
    BPL = 10,
    SIL = 11,
    DIL = 12,
    R8B = 13,
    R9B = 14,
    R10B = 15,
    R11B = 16,
    R12B = 17,
    R13B = 18,
    R14B = 19,
    R15B = 20,
    AX = 21,
    CX = 22,
    DX = 23,
    BX = 24,
    SP = 25,
    BP = 26,
    SI = 27,
    DI = 28,
    R8W = 29,
    R9W = 30,
    R10W = 31,
    R11W = 32,
    R12W = 33,
    R13W = 34,
    R14W = 35,
    R15W = 36,
    EAX = 37,
    ECX = 38,
    EDX = 39,
    EBX = 40,
    ESP = 41,
    EBP = 42,
    ESI = 43,
    EDI = 44,
    R8D = 45,
    R9D = 46,
    R10D = 47,
    R11D = 48,
    R12D = 49,
    R13D = 50,
    R14D = 51,
    R15D = 52,
    RAX = 53,
    RCX = 54,
    RDX = 55,
    RBX = 56,
    RSP = 57,
    RBP = 58,
    RSI = 59,
    RDI = 60,
    R8 = 61,
    R9 = 62,
    R10 = 63,
    R11 = 64,
    R12 = 65,
    R13 = 66,
    R14 = 67,
    R15 = 68,
    ST0 = 69,
    ST1 = 70,
    ST2 = 71,
    ST3 = 72,
    ST4 = 73,
    ST5 = 74,
    ST6 = 75,
    ST7 = 76,
    X87CONTROL = 77,
    X87STATUS = 78,
    X87TAG = 79,
    MM0 = 80,
    MM1 = 81,
    MM2 = 82,
    MM3 = 83,
    MM4 = 84,
    MM5 = 85,
    MM6 = 86,
    MM7 = 87,
    XMM0 = 88,
    XMM1 = 89,
    XMM2 = 90,
    XMM3 = 91,
    XMM4 = 92,
    XMM5 = 93,
    XMM6 = 94,
    XMM7 = 95,
    XMM8 = 96,
    XMM9 = 97,
    XMM10 = 98,
    XMM11 = 99,
    XMM12 = 100,
    XMM13 = 101,
    XMM14 = 102,
    XMM15 = 103,
    XMM16 = 104,
    XMM17 = 105,
    XMM18 = 106,
    XMM19 = 107,
    XMM20 = 108,
    XMM21 = 109,
    XMM22 = 110,
    XMM23 = 111,
    XMM24 = 112,
    XMM25 = 113,
    XMM26 = 114,
    XMM27 = 115,
    XMM28 = 116,
    XMM29 = 117,
    XMM30 = 118,
    XMM31 = 119,
    YMM0 = 120,
    YMM1 = 121,
    YMM2 = 122,
    YMM3 = 123,
    YMM4 = 124,
    YMM5 = 125,
    YMM6 = 126,
    YMM7 = 127,
    YMM8 = 128,
    YMM9 = 129,
    YMM10 = 130,
    YMM11 = 131,
    YMM12 = 132,
    YMM13 = 133,
    YMM14 = 134,
    YMM15 = 135,
    YMM16 = 136,
    YMM17 = 137,
    YMM18 = 138,
    YMM19 = 139,
    YMM20 = 140,
    YMM21 = 141,
    YMM22 = 142,
    YMM23 = 143,
    YMM24 = 144,
    YMM25 = 145,
    YMM26 = 146,
    YMM27 = 147,
    YMM28 = 148,
    YMM29 = 149,
    YMM30 = 150,
    YMM31 = 151,
    ZMM0 = 152,
    ZMM1 = 153,
    ZMM2 = 154,
    ZMM3 = 155,
    ZMM4 = 156,
    ZMM5 = 157,
    ZMM6 = 158,
    ZMM7 = 159,
    ZMM8 = 160,
    ZMM9 = 161,
    ZMM10 = 162,
    ZMM11 = 163,
    ZMM12 = 164,
    ZMM13 = 165,
    ZMM14 = 166,
    ZMM15 = 167,
    ZMM16 = 168,
    ZMM17 = 169,
    ZMM18 = 170,
    ZMM19 = 171,
    ZMM20 = 172,
    ZMM21 = 173,
    ZMM22 = 174,
    ZMM23 = 175,
    ZMM24 = 176,
    ZMM25 = 177,
    ZMM26 = 178,
    ZMM27 = 179,
    ZMM28 = 180,
    ZMM29 = 181,
    ZMM30 = 182,
    ZMM31 = 183,
    TMM0 = 184,
    TMM1 = 185,
    TMM2 = 186,
    TMM3 = 187,
    TMM4 = 188,
    TMM5 = 189,
    TMM6 = 190,
    TMM7 = 191,
    FLAGS = 192,
    EFLAGS = 193,
    RFLAGS = 194,
    IP = 195,
    EIP = 196,
    RIP = 197,
    ES = 198,
    CS = 199,
    SS = 200,
    DS = 201,
    FS = 202,
    GS = 203,
    GDTR = 204,
    LDTR = 205,
    IDTR = 206,
    TR = 207,
    TR0 = 208,
    TR1 = 209,
    TR2 = 210,
    TR3 = 211,
    TR4 = 212,
    TR5 = 213,
    TR6 = 214,
    TR7 = 215,
    CR0 = 216,
    CR1 = 217,
    CR2 = 218,
    CR3 = 219,
    CR4 = 220,
    CR5 = 221,
    CR6 = 222,
    CR7 = 223,
    CR8 = 224,
    CR9 = 225,
    CR10 = 226,
    CR11 = 227,
    CR12 = 228,
    CR13 = 229,
    CR14 = 230,
    CR15 = 231,
    DR0 = 232,
    DR1 = 233,
    DR2 = 234,
    DR3 = 235,
    DR4 = 236,
    DR5 = 237,
    DR6 = 238,
    DR7 = 239,
    DR8 = 240,
    DR9 = 241,
    DR10 = 242,
    DR11 = 243,
    DR12 = 244,
    DR13 = 245,
    DR14 = 246,
    DR15 = 247,
    K0 = 248,
    K1 = 249,
    K2 = 250,
    K3 = 251,
    K4 = 252,
    K5 = 253,
    K6 = 254,
    K7 = 255,
    BND0 = 256,
    BND1 = 257,
    BND2 = 258,
    BND3 = 259,
    BNDCFG = 260,
    BNDSTATUS = 261,
    MXCSR = 262,
    PKRU = 263,
    XCR0 = 264,
    UIF = 265,
}
impl Register {
    fn from_raw(raw: ZydisRegister) -> Result<Option<Self>> {
        if raw == ZydisRegister::ZYDIS_REGISTER_NONE {
            Ok(None)
        } else {
            let result =
                Self::try_from_primitive(raw.0).map_err(|_| Error::InvalidRegisterValue(raw.0))?;
            Ok(Some(result))
        }
    }
    fn from_raw_disallow_none(raw: ZydisRegister) -> Result<Self> {
        Self::from_raw(raw)?.ok_or(Error::UnexpectedNoneRegister)
    }
    fn to_raw(&self) -> ZydisRegister {
        ZydisRegister_(*self as u32)
    }

    /// tries to convert this register to a segment register, returning an error if it is not a segment register.
    pub fn to_segment_register(&self) -> Result<SegmentRegister> {
        SegmentRegister::from_register(*self)
    }
}

/// A segment register
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

/// An error returned from the zydis library.
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

    #[error("encountered an invalid register value {0:x}")]
    InvalidRegisterValue(u32),

    #[error("a register value of `None` was used somewhere were it didn't make sense")]
    UnexpectedNoneRegister,

    #[error(
        "a non-segment register ({0:?}) was used somewhere where a segment register was expected"
    )]
    ExpectedSegmentRegister(Register),

    #[error("encountered an invalid operand type {0:x}")]
    InvalidOperandType(u32),
}

/// the result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

#[bitfield_struct::bitfield(u32)]
struct ZyanStatusBitfield {
    #[bits(20)]
    code: u32,

    #[bits(11)]
    module: u32,

    is_error: bool,
}
