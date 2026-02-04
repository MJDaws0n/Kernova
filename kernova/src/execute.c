// execute.c
// x86/x86-64 instruction execution engine for Kernova
// Decodes and emulates instructions, outputting each one as it executes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "execute.h"

// ---------------------------------------------------------------------------
// x86/x86-64 Opcode tables and decoding helpers
// ---------------------------------------------------------------------------

// Register name tables for disassembly output
static const char* reg64_names[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char* reg32_names[] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};

static const char* reg16_names[] = {
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};

static const char* reg8_names[] = {
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};

// Legacy 8-bit register names (ah, ch, dh, bh) - kept for future use
// static const char* reg8_legacy[] = {
//     "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
// };

// ---------------------------------------------------------------------------
// Memory access helpers
// ---------------------------------------------------------------------------

static uint8_t read_byte(ExecutionContext* ctx, uint64_t addr) {
    uint64_t offset = addr - ctx->image_base;
    if (offset < ctx->memory_size) {
        return ctx->memory[offset];
    }
    return 0;
}

static uint16_t read_word(ExecutionContext* ctx, uint64_t addr) {
    return read_byte(ctx, addr) | ((uint16_t)read_byte(ctx, addr + 1) << 8);
}

static uint32_t read_dword(ExecutionContext* ctx, uint64_t addr) {
    return read_word(ctx, addr) | ((uint32_t)read_word(ctx, addr + 2) << 16);
}

static uint64_t read_qword(ExecutionContext* ctx, uint64_t addr) {
    return read_dword(ctx, addr) | ((uint64_t)read_dword(ctx, addr + 4) << 32);
}

static void write_byte(ExecutionContext* ctx, uint64_t addr, uint8_t val) {
    uint64_t offset = addr - ctx->image_base;
    if (offset < ctx->memory_size) {
        ctx->memory[offset] = val;
    }
}

static void write_word(ExecutionContext* ctx, uint64_t addr, uint16_t val) {
    write_byte(ctx, addr, val & 0xFF);
    write_byte(ctx, addr + 1, (val >> 8) & 0xFF);
}

static void write_dword(ExecutionContext* ctx, uint64_t addr, uint32_t val) {
    write_word(ctx, addr, val & 0xFFFF);
    write_word(ctx, addr + 2, (val >> 16) & 0xFFFF);
}

static void write_qword(ExecutionContext* ctx, uint64_t addr, uint64_t val) {
    write_dword(ctx, addr, val & 0xFFFFFFFF);
    write_dword(ctx, addr + 4, (val >> 32) & 0xFFFFFFFF);
}

// ---------------------------------------------------------------------------
// Register access by index
// ---------------------------------------------------------------------------

static uint64_t* get_reg64(CPUState* cpu, int reg) {
    switch (reg & 0xF) {
        case 0:  return &cpu->rax;
        case 1:  return &cpu->rcx;
        case 2:  return &cpu->rdx;
        case 3:  return &cpu->rbx;
        case 4:  return &cpu->rsp;
        case 5:  return &cpu->rbp;
        case 6:  return &cpu->rsi;
        case 7:  return &cpu->rdi;
        case 8:  return &cpu->r8;
        case 9:  return &cpu->r9;
        case 10: return &cpu->r10;
        case 11: return &cpu->r11;
        case 12: return &cpu->r12;
        case 13: return &cpu->r13;
        case 14: return &cpu->r14;
        case 15: return &cpu->r15;
    }
    return &cpu->rax;
}

// ---------------------------------------------------------------------------
// Flag manipulation
// ---------------------------------------------------------------------------

#define FLAG_CF (1ULL << 0)
#define FLAG_PF (1ULL << 2)
#define FLAG_AF (1ULL << 4)
#define FLAG_ZF (1ULL << 6)
#define FLAG_SF (1ULL << 7)
#define FLAG_OF (1ULL << 11)

static void update_flags_zsp(CPUState* cpu, uint64_t result, int bits) {
    uint64_t mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    result &= mask;
    
    // Zero flag
    if (result == 0) cpu->rflags |= FLAG_ZF;
    else cpu->rflags &= ~FLAG_ZF;
    
    // Sign flag
    uint64_t sign_bit = 1ULL << (bits - 1);
    if (result & sign_bit) cpu->rflags |= FLAG_SF;
    else cpu->rflags &= ~FLAG_SF;
    
    // Parity flag (low byte)
    int parity = 0;
    uint8_t low = result & 0xFF;
    while (low) { parity ^= (low & 1); low >>= 1; }
    if (!parity) cpu->rflags |= FLAG_PF;
    else cpu->rflags &= ~FLAG_PF;
}

// ---------------------------------------------------------------------------
// Instruction decoding
// ---------------------------------------------------------------------------

typedef struct {
    int has_rex;
    int rex_w;  // 64-bit operand
    int rex_r;  // ModRM.reg extension
    int rex_x;  // SIB.index extension
    int rex_b;  // ModRM.rm or SIB.base extension
    int has_operand_override;  // 0x66 prefix
    int has_address_override;  // 0x67 prefix
    int has_rep;    // 0xF3 prefix
    int has_repne;  // 0xF2 prefix
} Prefixes;

static size_t decode_prefixes(const uint8_t* code, size_t max_len, Prefixes* p) {
    memset(p, 0, sizeof(*p));
    size_t i = 0;
    while (i < max_len) {
        uint8_t b = code[i];
        if (b == 0x66) { p->has_operand_override = 1; i++; }
        else if (b == 0x67) { p->has_address_override = 1; i++; }
        else if (b == 0xF3) { p->has_rep = 1; i++; }
        else if (b == 0xF2) { p->has_repne = 1; i++; }
        else if ((b & 0xF0) == 0x40) {  // REX prefix (0x40-0x4F)
            p->has_rex = 1;
            p->rex_w = (b >> 3) & 1;
            p->rex_r = (b >> 2) & 1;
            p->rex_x = (b >> 1) & 1;
            p->rex_b = b & 1;
            i++;
        }
        else break;
    }
    return i;
}

static size_t decode_modrm_length(const uint8_t* code, int has_sib) {
    // has_sib parameter reserved for future SIB byte handling
    (void)has_sib;
    // Returns number of extra bytes for displacement
    uint8_t modrm = code[0];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm = modrm & 7;
    
    size_t len = 1;  // modrm byte
    
    if (mod == 3) {
        // Register direct
        return len;
    }
    
    // Check for SIB byte
    if (rm == 4 && mod != 3) {
        len++;  // SIB byte
    }
    
    if (mod == 0 && rm == 5) {
        len += 4;  // RIP-relative or disp32
    } else if (mod == 1) {
        len += 1;  // disp8
    } else if (mod == 2) {
        len += 4;  // disp32
    }
    
    return len;
}

// ---------------------------------------------------------------------------
// Disassembly string generation
// ---------------------------------------------------------------------------

static void decode_modrm_operand(ExecutionContext* ctx, const uint8_t* code, 
                                  Prefixes* p, int operand_size, 
                                  char* dest, size_t dest_size, int is_dest) {
    // Parameters reserved for future enhanced operand decoding
    (void)ctx;
    (void)is_dest;
    uint8_t modrm = code[0];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm = modrm & 7;
    int reg_idx = rm | (p->rex_b ? 8 : 0);
    
    const char** reg_table;
    if (operand_size == 64) reg_table = reg64_names;
    else if (operand_size == 32) reg_table = reg32_names;
    else if (operand_size == 16) reg_table = reg16_names;
    else reg_table = reg8_names;
    
    if (mod == 3) {
        snprintf(dest, dest_size, "%s", reg_table[reg_idx]);
    } else {
        // Memory operand - simplified
        const char* size_prefix = "";
        if (operand_size == 8) size_prefix = "byte ptr ";
        else if (operand_size == 16) size_prefix = "word ptr ";
        else if (operand_size == 32) size_prefix = "dword ptr ";
        else if (operand_size == 64) size_prefix = "qword ptr ";
        
        if (mod == 0 && rm == 5) {
            int32_t disp = *(int32_t*)(code + 1);
            snprintf(dest, dest_size, "%s[rip+0x%x]", size_prefix, disp);
        } else {
            snprintf(dest, dest_size, "%s[%s]", size_prefix, reg64_names[reg_idx]);
        }
    }
}

// ---------------------------------------------------------------------------
// Main instruction decoder
// ---------------------------------------------------------------------------

int decode_instruction(ExecutionContext* ctx, uint64_t address, DecodedInstruction* out) {
    memset(out, 0, sizeof(*out));
    out->address = address;
    
    uint64_t offset = address - ctx->image_base;
    if (offset >= ctx->memory_size) {
        strcpy(out->mnemonic, "???");
        strcpy(out->full_text, "??? (invalid address)");
        return -1;
    }
    
    const uint8_t* code = ctx->memory + offset;
    size_t remaining = ctx->memory_size - offset;
    if (remaining > 15) remaining = 15;
    
    Prefixes p;
    size_t pos = decode_prefixes(code, remaining, &p);
    
    // Operand size determination (used implicitly via p.rex_w in instruction decode)
    (void)(p.rex_w ? 64 : (p.has_operand_override ? 16 : 32));
    
    uint8_t opcode = code[pos++];
    
    // Copy raw bytes
    size_t total_len = pos;
    
    // Decode common instructions
    switch (opcode) {
        // NOP
        case 0x90:
            strcpy(out->mnemonic, "nop");
            out->operands[0] = '\0';
            break;
            
        // RET variants
        case 0xC3:
            strcpy(out->mnemonic, "ret");
            out->operands[0] = '\0';
            break;
        case 0xC2: {
            uint16_t imm = *(uint16_t*)(code + pos);
            total_len += 2;
            strcpy(out->mnemonic, "ret");
            snprintf(out->operands, sizeof(out->operands), "0x%x", imm);
            break;
        }
        
        // PUSH r64
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57: {
            int reg = (opcode - 0x50) | (p.rex_b ? 8 : 0);
            strcpy(out->mnemonic, "push");
            snprintf(out->operands, sizeof(out->operands), "%s", reg64_names[reg]);
            break;
        }
        
        // POP r64
        case 0x58: case 0x59: case 0x5A: case 0x5B:
        case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            int reg = (opcode - 0x58) | (p.rex_b ? 8 : 0);
            strcpy(out->mnemonic, "pop");
            snprintf(out->operands, sizeof(out->operands), "%s", reg64_names[reg]);
            break;
        }
        
        // MOV r64, imm64 (REX.W + B8+rd)
        case 0xB8: case 0xB9: case 0xBA: case 0xBB:
        case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            int reg = (opcode - 0xB8) | (p.rex_b ? 8 : 0);
            strcpy(out->mnemonic, "mov");
            if (p.rex_w) {
                uint64_t imm = *(uint64_t*)(code + pos);
                total_len += 8;
                snprintf(out->operands, sizeof(out->operands), "%s, 0x%llx", 
                         reg64_names[reg], (unsigned long long)imm);
            } else {
                uint32_t imm = *(uint32_t*)(code + pos);
                total_len += 4;
                snprintf(out->operands, sizeof(out->operands), "%s, 0x%x", 
                         reg32_names[reg], imm);
            }
            break;
        }
        
        // MOV r/m, r or MOV r, r/m
        case 0x89: case 0x8B: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            
            strcpy(out->mnemonic, "mov");
            const char** names = p.rex_w ? reg64_names : reg32_names;
            
            if ((modrm >> 6) == 3) {  // Register-to-register
                if (opcode == 0x89) {
                    snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                             names[rm], names[reg]);
                } else {
                    snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                             names[reg], names[rm]);
                }
            } else {
                // Memory operand - simplified
                char mem_str[32];
                decode_modrm_operand(ctx, code + pos, &p, p.rex_w ? 64 : 32, 
                                    mem_str, sizeof(mem_str), 0);
                if (opcode == 0x89) {
                    snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                             mem_str, names[reg]);
                } else {
                    snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                             names[reg], mem_str);
                }
            }
            break;
        }
        
        // SUB r/m, imm8 or other 83 /5 forms
        case 0x83: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int op_ext = (modrm >> 3) & 7;
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            int8_t imm = *(int8_t*)(code + total_len);
            total_len += 1;
            
            const char* ops[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
            strcpy(out->mnemonic, ops[op_ext]);
            
            const char** names = p.rex_w ? reg64_names : reg32_names;
            if ((modrm >> 6) == 3) {
                snprintf(out->operands, sizeof(out->operands), "%s, 0x%x", 
                         names[rm], (uint8_t)imm);
            } else {
                snprintf(out->operands, sizeof(out->operands), "[...], 0x%x", (uint8_t)imm);
            }
            break;
        }
        
        // ADD, OR, ADC, SBB, AND, SUB, XOR, CMP r/m, r
        case 0x01: case 0x09: case 0x11: case 0x19:
        case 0x21: case 0x29: case 0x31: case 0x39: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            
            const char* ops[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
            strcpy(out->mnemonic, ops[(opcode >> 3) & 7]);
            
            const char** names = p.rex_w ? reg64_names : reg32_names;
            if ((modrm >> 6) == 3) {
                snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                         names[rm], names[reg]);
            } else {
                snprintf(out->operands, sizeof(out->operands), "[...], %s", names[reg]);
            }
            break;
        }
        
        // XOR r, r/m
        case 0x33: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            
            strcpy(out->mnemonic, "xor");
            const char** names = p.rex_w ? reg64_names : reg32_names;
            if ((modrm >> 6) == 3) {
                snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                         names[reg], names[rm]);
            } else {
                snprintf(out->operands, sizeof(out->operands), "%s, [...]", names[reg]);
            }
            break;
        }
        
        // LEA r, m
        case 0x8D: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
            
            strcpy(out->mnemonic, "lea");
            const char** names = p.rex_w ? reg64_names : reg32_names;
            char mem_str[32];
            decode_modrm_operand(ctx, code + pos, &p, p.rex_w ? 64 : 32, 
                                mem_str, sizeof(mem_str), 0);
            snprintf(out->operands, sizeof(out->operands), "%s, %s", names[reg], mem_str);
            break;
        }
        
        // CALL rel32
        case 0xE8: {
            int32_t rel = *(int32_t*)(code + pos);
            total_len += 4;
            strcpy(out->mnemonic, "call");
            uint64_t target = address + total_len + rel;
            snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
            break;
        }
        
        // JMP rel8
        case 0xEB: {
            int8_t rel = *(int8_t*)(code + pos);
            total_len += 1;
            strcpy(out->mnemonic, "jmp");
            uint64_t target = address + total_len + rel;
            snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
            break;
        }
        
        // JMP rel32
        case 0xE9: {
            int32_t rel = *(int32_t*)(code + pos);
            total_len += 4;
            strcpy(out->mnemonic, "jmp");
            uint64_t target = address + total_len + rel;
            snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
            break;
        }
        
        // Jcc rel8 (short conditional jumps)
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B:
        case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            int8_t rel = *(int8_t*)(code + pos);
            total_len += 1;
            const char* jcc_names[] = {
                "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            strcpy(out->mnemonic, jcc_names[opcode - 0x70]);
            uint64_t target = address + total_len + rel;
            snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
            break;
        }
        
        // Two-byte opcodes (0F prefix)
        case 0x0F: {
            if (pos >= remaining) {
                strcpy(out->mnemonic, "???");
                break;
            }
            uint8_t opcode2 = code[pos++];
            total_len++;
            
            // Jcc rel32 (0F 80-8F)
            if (opcode2 >= 0x80 && opcode2 <= 0x8F) {
                int32_t rel = *(int32_t*)(code + pos);
                total_len += 4;
                const char* jcc_names[] = {
                    "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
                };
                strcpy(out->mnemonic, jcc_names[opcode2 - 0x80]);
                uint64_t target = address + total_len + rel;
                snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
            }
            // MOVZX, MOVSX
            else if (opcode2 == 0xB6 || opcode2 == 0xB7 || opcode2 == 0xBE || opcode2 == 0xBF) {
                total_len += decode_modrm_length(code + pos, 0);
                uint8_t modrm = code[pos];
                int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
                
                if (opcode2 == 0xB6) strcpy(out->mnemonic, "movzx");
                else if (opcode2 == 0xB7) strcpy(out->mnemonic, "movzx");
                else if (opcode2 == 0xBE) strcpy(out->mnemonic, "movsx");
                else strcpy(out->mnemonic, "movsx");
                
                const char** names = p.rex_w ? reg64_names : reg32_names;
                snprintf(out->operands, sizeof(out->operands), "%s, ...", names[reg]);
            }
            // SYSCALL
            else if (opcode2 == 0x05) {
                strcpy(out->mnemonic, "syscall");
                out->operands[0] = '\0';
            }
            // CPUID
            else if (opcode2 == 0xA2) {
                strcpy(out->mnemonic, "cpuid");
                out->operands[0] = '\0';
            }
            else {
                snprintf(out->mnemonic, sizeof(out->mnemonic), "0f %02x", opcode2);
                out->operands[0] = '\0';
            }
            break;
        }
        
        // INT 3 (breakpoint)
        case 0xCC:
            strcpy(out->mnemonic, "int3");
            out->operands[0] = '\0';
            break;
            
        // INT imm8
        case 0xCD: {
            uint8_t imm = code[pos];
            total_len += 1;
            strcpy(out->mnemonic, "int");
            snprintf(out->operands, sizeof(out->operands), "0x%x", imm);
            break;
        }
        
        // HLT
        case 0xF4:
            strcpy(out->mnemonic, "hlt");
            out->operands[0] = '\0';
            break;
            
        // TEST r/m, r
        case 0x85: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int reg = ((modrm >> 3) & 7) | (p.rex_r ? 8 : 0);
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            
            strcpy(out->mnemonic, "test");
            const char** names = p.rex_w ? reg64_names : reg32_names;
            if ((modrm >> 6) == 3) {
                snprintf(out->operands, sizeof(out->operands), "%s, %s", 
                         names[rm], names[reg]);
            } else {
                snprintf(out->operands, sizeof(out->operands), "[...], %s", names[reg]);
            }
            break;
        }
        
        // INC/DEC r64 with 0xFF prefix
        case 0xFF: {
            total_len += decode_modrm_length(code + pos, 0);
            uint8_t modrm = code[pos];
            int op_ext = (modrm >> 3) & 7;
            int rm = (modrm & 7) | (p.rex_b ? 8 : 0);
            
            const char* ops[] = {"inc", "dec", "call", "call", "jmp", "jmp", "push", "???"};
            strcpy(out->mnemonic, ops[op_ext]);
            
            const char** names = p.rex_w ? reg64_names : reg32_names;
            if ((modrm >> 6) == 3) {
                snprintf(out->operands, sizeof(out->operands), "%s", names[rm]);
            } else {
                snprintf(out->operands, sizeof(out->operands), "[...]");
            }
            break;
        }
        
        default:
            snprintf(out->mnemonic, sizeof(out->mnemonic), "db");
            snprintf(out->operands, sizeof(out->operands), "0x%02x", opcode);
            break;
    }
    
    out->length = total_len;
    memcpy(out->bytes, code, total_len > 16 ? 16 : total_len);
    
    // Build full text
    if (out->operands[0]) {
        snprintf(out->full_text, sizeof(out->full_text), "%s %s", 
                 out->mnemonic, out->operands);
    } else {
        snprintf(out->full_text, sizeof(out->full_text), "%s", out->mnemonic);
    }
    
    return 0;
}

// ---------------------------------------------------------------------------
// Instruction execution (simplified emulation)
// ---------------------------------------------------------------------------

static int execute_instruction(ExecutionContext* ctx, const DecodedInstruction* instr) {
    CPUState* cpu = &ctx->cpu;
    
    // NOP
    if (strcmp(instr->mnemonic, "nop") == 0) {
        // Do nothing
    }
    // RET
    else if (strcmp(instr->mnemonic, "ret") == 0) {
        cpu->rip = read_qword(ctx, cpu->rsp);
        cpu->rsp += 8;
        return 0;  // Don't advance RIP normally
    }
    // PUSH
    else if (strcmp(instr->mnemonic, "push") == 0) {
        // Parse register from operands
        for (int i = 0; i < 16; i++) {
            if (strstr(instr->operands, reg64_names[i])) {
                cpu->rsp -= 8;
                write_qword(ctx, cpu->rsp, *get_reg64(cpu, i));
                break;
            }
        }
    }
    // POP
    else if (strcmp(instr->mnemonic, "pop") == 0) {
        for (int i = 0; i < 16; i++) {
            if (strstr(instr->operands, reg64_names[i])) {
                *get_reg64(cpu, i) = read_qword(ctx, cpu->rsp);
                cpu->rsp += 8;
                break;
            }
        }
    }
    // XOR (for xor reg, reg -> zero register)
    else if (strcmp(instr->mnemonic, "xor") == 0) {
        // Simple case: xor reg, reg (zero the register)
        for (int i = 0; i < 16; i++) {
            char pattern[32];
            snprintf(pattern, sizeof(pattern), "%s, %s", reg64_names[i], reg64_names[i]);
            if (strcmp(instr->operands, pattern) == 0) {
                *get_reg64(cpu, i) = 0;
                update_flags_zsp(cpu, 0, 64);
                break;
            }
            snprintf(pattern, sizeof(pattern), "%s, %s", reg32_names[i], reg32_names[i]);
            if (strcmp(instr->operands, pattern) == 0) {
                *get_reg64(cpu, i) = 0;  // 32-bit op zeros upper 32 bits
                update_flags_zsp(cpu, 0, 32);
                break;
            }
        }
    }
    // SUB
    else if (strcmp(instr->mnemonic, "sub") == 0) {
        // Simplified: just handle common patterns
        if (strstr(instr->operands, "rsp,")) {
            char* comma = strchr(instr->operands, ',');
            if (comma) {
                uint64_t imm = strtoull(comma + 1, NULL, 0);
                cpu->rsp -= imm;
            }
        }
    }
    // ADD
    else if (strcmp(instr->mnemonic, "add") == 0) {
        if (strstr(instr->operands, "rsp,")) {
            char* comma = strchr(instr->operands, ',');
            if (comma) {
                uint64_t imm = strtoull(comma + 1, NULL, 0);
                cpu->rsp += imm;
            }
        }
    }
    // CALL
    else if (strcmp(instr->mnemonic, "call") == 0) {
        uint64_t target = strtoull(instr->operands, NULL, 0);
        cpu->rsp -= 8;
        write_qword(ctx, cpu->rsp, cpu->rip + instr->length);
        cpu->rip = target;
        return 0;  // Don't advance RIP
    }
    // JMP
    else if (strcmp(instr->mnemonic, "jmp") == 0) {
        uint64_t target = strtoull(instr->operands, NULL, 0);
        cpu->rip = target;
        return 0;  // Don't advance RIP
    }
    // Conditional jumps (simplified - just check ZF for jz/jnz)
    else if (strcmp(instr->mnemonic, "jz") == 0 || strcmp(instr->mnemonic, "je") == 0) {
        if (cpu->rflags & FLAG_ZF) {
            cpu->rip = strtoull(instr->operands, NULL, 0);
            return 0;
        }
    }
    else if (strcmp(instr->mnemonic, "jnz") == 0 || strcmp(instr->mnemonic, "jne") == 0) {
        if (!(cpu->rflags & FLAG_ZF)) {
            cpu->rip = strtoull(instr->operands, NULL, 0);
            return 0;
        }
    }
    // HLT - halt execution
    else if (strcmp(instr->mnemonic, "hlt") == 0) {
        ctx->halted = 1;
    }
    // INT3 - breakpoint, halt
    else if (strcmp(instr->mnemonic, "int3") == 0) {
        ctx->halted = 1;
    }
    // SYSCALL - would need OS emulation, just halt for now
    else if (strcmp(instr->mnemonic, "syscall") == 0) {
        printf("  [SYSCALL] rax=0x%llx (syscall number)\n", (unsigned long long)cpu->rax);
        ctx->halted = 1;
    }
    
    // Advance RIP by instruction length
    cpu->rip += instr->length;
    return 0;
}

// ---------------------------------------------------------------------------
// Public API Implementation
// ---------------------------------------------------------------------------

int execute_init(ExecutionContext* ctx,
                 const unsigned char* file_data,
                 size_t file_len,
                 int is_64bit) {
    memset(ctx, 0, sizeof(*ctx));

    ctx->backend = EXEC_BACKEND_SIMPLE;
    
    if (!file_data || file_len < 64) return -1;
    
    // Parse PE headers to find entry point and code section
    uint32_t e_lfanew = *(uint32_t*)(file_data + 60);
    if (e_lfanew + 24 > file_len) return -2;
    
    // Check PE signature
    if (memcmp(file_data + e_lfanew, "PE\0\0", 4) != 0) return -3;
    
    const unsigned char* coff = file_data + e_lfanew + 4;
    uint16_t num_sections = *(uint16_t*)(coff + 2);
    uint16_t opt_header_size = *(uint16_t*)(coff + 16);
    
    const unsigned char* opt = coff + 20;
    
    // Read image base and entry point from optional header
    uint64_t image_base;
    uint32_t entry_point_rva;
    
    if (is_64bit) {
        // PE32+ format
        image_base = *(uint64_t*)(opt + 24);
        entry_point_rva = *(uint32_t*)(opt + 16);
    } else {
        // PE32 format
        image_base = *(uint32_t*)(opt + 28);
        entry_point_rva = *(uint32_t*)(opt + 16);
    }
    
    ctx->image_base = image_base;
    ctx->entry_point = entry_point_rva;
    
    // Find .text section
    const unsigned char* sections = opt + opt_header_size;
    for (int i = 0; i < num_sections; i++) {
        const unsigned char* sec = sections + (i * 40);
        char name[9] = {0};
        memcpy(name, sec, 8);
        
        if (strncmp(name, ".text", 5) == 0) {
            uint32_t virtual_size = *(uint32_t*)(sec + 8);
            uint32_t virtual_addr = *(uint32_t*)(sec + 12);
            ctx->code_start = image_base + virtual_addr;
            ctx->code_end = ctx->code_start + virtual_size;
            break;
        }
    }
    
    // Allocate memory and copy file
    // For simplicity, we allocate enough to cover the image
    size_t mem_size = file_len;
    if (mem_size < 0x10000) mem_size = 0x10000;  // Minimum size
    
    ctx->memory = calloc(1, mem_size);
    if (!ctx->memory) return -4;
    ctx->memory_size = mem_size;
    
    // Copy file data
    memcpy(ctx->memory, file_data, file_len);
    
    // Initialize CPU state
    ctx->cpu.rip = image_base + entry_point_rva;
    ctx->cpu.rsp = image_base + mem_size - 0x1000;  // Stack at top of memory
    ctx->cpu.rbp = ctx->cpu.rsp;
    ctx->cpu.rflags = 0x202;  // IF set
    
    ctx->halted = 0;
    ctx->instruction_count = 0;
    ctx->verbose = 1;  // Output instructions by default
    
    return 0;
}

int execute_step(ExecutionContext* ctx) {
    if (ctx->halted) return 1;
    
    DecodedInstruction instr;
    if (decode_instruction(ctx, ctx->cpu.rip, &instr) < 0) {
        ctx->halted = 1;
        return -1;
    }
    
    // Output the instruction being executed
    if (ctx->verbose) {
        print_instruction(&instr);
    }
    
    // Execute the instruction
    (void)execute_instruction(ctx, &instr);
    ctx->instruction_count++;
    
    // Check if we've gone outside code section
    if (ctx->cpu.rip < ctx->code_start || ctx->cpu.rip >= ctx->code_end) {
        // Allow some slack for returns/calls, but eventually halt
        if (ctx->cpu.rip < ctx->image_base || 
            ctx->cpu.rip >= ctx->image_base + ctx->memory_size) {
            ctx->halted = 1;
        }
    }
    
    return ctx->halted ? 1 : 0;
}

size_t execute_run(ExecutionContext* ctx, size_t max_instructions) {
    size_t count = 0;
    
    printf("\n══════════════════════════════════════════════════════════════════\n");
    printf("  INSTRUCTION EXECUTION TRACE\n");
    printf("══════════════════════════════════════════════════════════════════\n");
    printf("Entry Point: 0x%llx\n", (unsigned long long)(ctx->image_base + ctx->entry_point));
    printf("Code Section: 0x%llx - 0x%llx\n", 
           (unsigned long long)ctx->code_start, (unsigned long long)ctx->code_end);
    printf("──────────────────────────────────────────────────────────────────\n\n");
    
    while (!ctx->halted && count < max_instructions) {
        int result = execute_step(ctx);
        count++;
        if (result != 0) break;
    }
    
    printf("\n──────────────────────────────────────────────────────────────────\n");
    printf("Execution %s after %zu instructions\n", 
           ctx->halted ? "halted" : "paused (limit reached)", count);
    printf("══════════════════════════════════════════════════════════════════\n");
    
    return count;
}

void print_instruction(const DecodedInstruction* instr) {
    // Format: ADDRESS | BYTES | DISASSEMBLY
    printf("0x%08llx │ ", (unsigned long long)instr->address);
    
    // Print hex bytes (up to 8 bytes shown)
    for (size_t i = 0; i < 8; i++) {
        if (i < instr->length) {
            printf("%02x ", instr->bytes[i]);
        } else {
            printf("   ");
        }
    }
    
    printf("│ %s\n", instr->full_text);
}

void print_cpu_state(const CPUState* cpu, int is_64bit) {
    printf("\n┌─────────────────────────────────────────────────────────────┐\n");
    printf("│ CPU State                                                   │\n");
    printf("├─────────────────────────────────────────────────────────────┤\n");
    
    if (is_64bit) {
        printf("│ RAX: %016llx  RBX: %016llx │\n", 
               (unsigned long long)cpu->rax, (unsigned long long)cpu->rbx);
        printf("│ RCX: %016llx  RDX: %016llx │\n", 
               (unsigned long long)cpu->rcx, (unsigned long long)cpu->rdx);
        printf("│ RSI: %016llx  RDI: %016llx │\n", 
               (unsigned long long)cpu->rsi, (unsigned long long)cpu->rdi);
        printf("│ RBP: %016llx  RSP: %016llx │\n", 
               (unsigned long long)cpu->rbp, (unsigned long long)cpu->rsp);
        printf("│ R8:  %016llx  R9:  %016llx │\n", 
               (unsigned long long)cpu->r8, (unsigned long long)cpu->r9);
        printf("│ R10: %016llx  R11: %016llx │\n", 
               (unsigned long long)cpu->r10, (unsigned long long)cpu->r11);
        printf("│ R12: %016llx  R13: %016llx │\n", 
               (unsigned long long)cpu->r12, (unsigned long long)cpu->r13);
        printf("│ R14: %016llx  R15: %016llx │\n", 
               (unsigned long long)cpu->r14, (unsigned long long)cpu->r15);
    } else {
        printf("│ EAX: %08llx  EBX: %08llx  ECX: %08llx  EDX: %08llx │\n",
               (unsigned long long)(cpu->rax & 0xFFFFFFFF),
               (unsigned long long)(cpu->rbx & 0xFFFFFFFF),
               (unsigned long long)(cpu->rcx & 0xFFFFFFFF),
               (unsigned long long)(cpu->rdx & 0xFFFFFFFF));
        printf("│ ESI: %08llx  EDI: %08llx  EBP: %08llx  ESP: %08llx │\n",
               (unsigned long long)(cpu->rsi & 0xFFFFFFFF),
               (unsigned long long)(cpu->rdi & 0xFFFFFFFF),
               (unsigned long long)(cpu->rbp & 0xFFFFFFFF),
               (unsigned long long)(cpu->rsp & 0xFFFFFFFF));
    }
    
    printf("│ RIP: %016llx  RFLAGS: %016llx │\n",
           (unsigned long long)cpu->rip, (unsigned long long)cpu->rflags);
    printf("│ Flags: [%c%c%c%c%c%c]                                           │\n",
           (cpu->rflags & FLAG_CF) ? 'C' : '-',
           (cpu->rflags & FLAG_PF) ? 'P' : '-',
           (cpu->rflags & FLAG_AF) ? 'A' : '-',
           (cpu->rflags & FLAG_ZF) ? 'Z' : '-',
           (cpu->rflags & FLAG_SF) ? 'S' : '-',
           (cpu->rflags & FLAG_OF) ? 'O' : '-');
    printf("└─────────────────────────────────────────────────────────────┘\n");
}

void execute_cleanup(ExecutionContext* ctx) {
    if (ctx->memory) {
        free(ctx->memory);
        ctx->memory = NULL;
    }
    ctx->memory_size = 0;
    ctx->halted = 1;
}

void format_instruction(const DecodedInstruction* instr, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "0x%08llx: %s",
             (unsigned long long)instr->address, instr->full_text);
}
