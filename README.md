# rydis

this is a crate which allows encoding, decoding and working with x86 instructions in a very convenient and user-friendly way.

it uses the `Zydis` library under the hood, but provides user-friendly wrappers around `Zydis`' interfaces to make it
easier to work with.

## Example
```rust
let state = rydis::RydisState::new(MachineMode::Long64, StackWidth::Width64)?;

// encode an instruction
let encoded = state.encode(Instruction {
    prefixes: Prefixes::empty(),
    mnemonic: Mnemonic::XCHG,
    operands: [Operand::Reg(Register::RAX), Operand::Reg(Register::RBX)]
        .into_iter()
        .collect(),
})?;

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

// format it
println!(
    "modified insn: {}",
    modified_instruction.format(&state, FormatStyle::Intel, Some(0x123400))?
);

// re-encode the modified instruction
let re_encoded = state.encode(modified_instruction)?;
```
