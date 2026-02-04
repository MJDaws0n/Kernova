// execute.h
#ifndef EXECUTE_H
#define EXECUTE_H

#include <stdint.h>
#include <stddef.h>

// CPU Register set for x86-64 emulation
typedef struct {
    // General purpose registers (64-bit)
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    
    // Instruction pointer
    uint64_t rip;
    
    // Flags register
    uint64_t rflags;
    
    // Segment registers (for completeness)
    uint16_t cs, ds, es, fs, gs, ss;
} CPUState;

// Decoded instruction representation
typedef struct {
    uint64_t address;           // Virtual address of instruction
    uint8_t  bytes[16];         // Raw instruction bytes (max x86 instruction = 15 bytes)
    size_t   length;            // Instruction length in bytes
    char     mnemonic[16];      // Instruction mnemonic (mov, push, etc.)
    char     operands[64];      // Operand string representation
    char     full_text[96];     // Full disassembly text
} DecodedInstruction;

// Execution context holding everything needed for emulation
typedef struct {
    CPUState          cpu;              // CPU register state
    unsigned char*    memory;           // Flat memory image
    size_t            memory_size;      // Size of allocated memory
    uint64_t          image_base;       // PE image base address
    uint64_t          entry_point;      // Entry point RVA
    uint64_t          code_start;       // Start of .text section (VA)
    uint64_t          code_end;         // End of .text section (VA)
    int               halted;           // 1 if execution should stop
    size_t            instruction_count;// Number of instructions executed
    int               verbose;          // Output each instruction

    // Backend implementation details
    // backend == 1: internal lightweight decoder/emulator (best-effort)
    // backend == 2: Unicorn CPU emulation + Capstone disassembly (accurate)
    int               backend;
    void*             uc;               // unicorn_engine*
    void*             cs;               // csh* (stored indirectly)
    uint64_t          stack_base;
    uint64_t          stack_size;
} ExecutionContext;

#define EXEC_BACKEND_SIMPLE  1
#define EXEC_BACKEND_UNICORN 2

// Initialize execution context from PE data
// Returns 0 on success, non-zero on error
int execute_init(ExecutionContext* ctx,
                 const unsigned char* file_data,
                 size_t file_len,
                 int is_64bit);

// Execute a single instruction at the current RIP
// Returns 0 on success, 1 if halted/finished, negative on error
int execute_step(ExecutionContext* ctx);

// Execute until halted or max_instructions reached
// Returns number of instructions executed
size_t execute_run(ExecutionContext* ctx, size_t max_instructions);

// Decode instruction at given address without executing
int decode_instruction(ExecutionContext* ctx, uint64_t address, DecodedInstruction* out);

// Print instruction in a formatted way
void print_instruction(const DecodedInstruction* instr);

// Print current CPU state
void print_cpu_state(const CPUState* cpu, int is_64bit);

// Free execution context resources
void execute_cleanup(ExecutionContext* ctx);

// Helper to format instruction for output
void format_instruction(const DecodedInstruction* instr, char* buffer, size_t buffer_size);

#endif
