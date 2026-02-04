# Kernova
https://mjdawson.net/projects/kernova

A virtual kernel / x86-64 emulator that parses PE (Windows) executables and executes their instructions.

## Features
- **PE File Parsing**: Reads and parses DOS Header, PE Signature, COFF Header, Optional Header, and Section Headers
- **Architecture Detection**: Determines if executable is 32-bit or 64-bit
- **Instruction Execution Engine**: Decodes and emulates x86/x86-64 instructions
- **Instruction Tracing**: Outputs every assembly instruction as it executes with address, bytes, and disassembly
- **CPU State Emulation**: Maintains virtual CPU registers (RAX-R15, RIP, RFLAGS, etc.)

## Build and Run
```bash
make -C ./kernova && ./kernova/build/kernova_bin example.exe
```

## Output Example
```
══════════════════════════════════════════════════════════════════
  INSTRUCTION EXECUTION TRACE
══════════════════════════════════════════════════════════════════
Entry Point: 0x140001125
Code Section: 0x140001000 - 0x1400032d8
──────────────────────────────────────────────────────────────────

0x140001125 │ 48 89 c0             │ mov rax, rax
0x140001128 │ 55                   │ push rbp
0x140001129 │ 48 89 e5             │ mov rbp, rsp
...
```

## Header Information
1.	DOS Header → file_bytes[0:64]
2.	DOS Stub → file_bytes[64:e_lfanew]
3.	PE Signature → file_bytes[e_lfanew:e_lfanew+4]
4.	COFF Header → file_bytes[e_lfanew+4:e_lfanew+24]
5.	Optional Header → file_bytes[e_lfanew+24:e_lfanew+24+OptionalHeaderSize]
6.	Section Headers → file_bytes[e_lfanew+24+OptionalHeaderSize: e_lfanew+24+OptionalHeaderSize + NumberOfSections*40]

## Architecture
- **parse.c**: PE file parsing and main execution flow
- **execute.c**: x86/x86-64 instruction decoder and emulator
- **parse_sections.c**: Section header parsing and data extraction
- **startup.c**: Initialization and version display
- **main.c**: Entry point

## Supported Instructions
Common x86-64 instructions including:
- Data movement: MOV, PUSH, POP, LEA, MOVZX, MOVSX
- Arithmetic: ADD, SUB, XOR, AND, OR, CMP, TEST, INC, DEC
- Control flow: CALL, RET, JMP, Jcc (conditional jumps)
- System: SYSCALL, INT, HLT, NOP

## Version History
- **v0.2**: Execution Engine - Instruction tracing and emulation
- **v0.1**: Proof of Concept - PE parsing and section analysis