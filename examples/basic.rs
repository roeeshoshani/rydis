use rydis::{
    Instruction, MachineMode, MemOperand, Mnemonic, Operand, Prefixes, Register, StackWidth,
};

fn main() -> rydis::Result<()> {
    let state = rydis::RydisState::new(MachineMode::Long64, StackWidth::Width64)?;

    // encode an instruction
    let encoded = state.encode(Instruction {
        prefixes: Prefixes::empty(),
        mnemonic: Mnemonic::XCHG,
        operands: [Operand::Reg(Register::RAX), Operand::Reg(Register::RBX)]
            .into_iter()
            .collect(),
    })?;
    println!("encoded = {:x?}", encoded);

    // decode it
    let decoded_instruction = state.decode_one(encoded.as_slice())?;

    // modify it
    let mut modified_instruction = decoded_instruction.to_instruction();
    modified_instruction.operands[1] = Operand::Mem(MemOperand {
        base: Some(Register::RBP),
        index: None,
        displacement: 0x1234,
        size: decoded_instruction.operand_width,
        segment_register_override: None,
    });

    // re-encode the modified instruction
    let re_encoded = state.encode(modified_instruction)?;
    println!("re-encoded = {:x?}", re_encoded);

    Ok(())
}
