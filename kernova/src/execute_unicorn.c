// execute_unicorn.c
// Accurate x86/x86-64 instruction execution + tracing via Unicorn (CPU) + Capstone (disasm)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main.h"
#include "execute.h"

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#define PAGE_ALIGN 0x1000ULL

static uint64_t align_up(uint64_t value, uint64_t align) {
    return (value + (align - 1)) & ~(align - 1);
}

typedef struct {
    uc_engine* uc;
    csh cs;
    int is_64bit;
    int printed_backend_banner;
} UnicornBackend;

static void print_trace_header(const ExecutionContext* ctx) {
    printf("\n══════════════════════════════════════════════════════════════════\n");
    printf("  INSTRUCTION EXECUTION TRACE (Unicorn + Capstone)\n");
    printf("══════════════════════════════════════════════════════════════════\n");
    printf("Entry Point: 0x%llx\n", (unsigned long long)(ctx->image_base + ctx->entry_point));
    printf("Code Section: 0x%llx - 0x%llx\n",
           (unsigned long long)ctx->code_start,
           (unsigned long long)ctx->code_end);
    printf("──────────────────────────────────────────────────────────────────\n\n");
}

static void print_bytes_column(const uint8_t* bytes, size_t size, size_t max) {
    for (size_t i = 0; i < max; i++) {
        if (i < size) printf("%02x ", bytes[i]);
        else printf("   ");
    }
}

static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    ExecutionContext* ctx = (ExecutionContext*)user_data;
    UnicornBackend* b = (UnicornBackend*)ctx->uc;

    if (!ctx->verbose) return;

    uint8_t buf[16] = {0};
    size_t to_read = size;
    if (to_read > sizeof(buf)) to_read = sizeof(buf);

    if (uc_mem_read(uc, address, buf, to_read) != UC_ERR_OK) {
        printf("0x%08llx │ ", (unsigned long long)address);
        print_bytes_column(buf, 0, 8);
        printf("│ <unreadable>\n");
        return;
    }

    cs_insn* insn = NULL;
    size_t count = cs_disasm(b->cs, buf, to_read, address, 1, &insn);

    if (count == 0 || !insn) {
        printf("0x%08llx │ ", (unsigned long long)address);
        print_bytes_column(buf, to_read, 8);
        printf("│ db 0x%02x\n", buf[0]);
        if (insn) cs_free(insn, count);
        return;
    }

    printf("0x%08llx │ ", (unsigned long long)address);
    print_bytes_column(insn[0].bytes, insn[0].size, 8);
    if (insn[0].op_str && insn[0].op_str[0]) {
        printf("│ %s %s\n", insn[0].mnemonic, insn[0].op_str);
    } else {
        printf("│ %s\n", insn[0].mnemonic);
    }

    // Stop on instructions that would require OS/ABI emulation.
    if (strcmp(insn[0].mnemonic, "syscall") == 0 ||
        strcmp(insn[0].mnemonic, "int") == 0 ||
        strcmp(insn[0].mnemonic, "hlt") == 0) {
        ctx->halted = 1;
        uc_emu_stop(uc);
    }

    cs_free(insn, count);
    ctx->instruction_count++;
}

static bool hook_mem_invalid(uc_engine* uc,
                             uc_mem_type type,
                             uint64_t address,
                             int size,
                             int64_t value,
                             void* user_data) {
    (void)type;
    (void)size;
    (void)value;

    ExecutionContext* ctx = (ExecutionContext*)user_data;
    ctx->halted = 1;

    uint64_t rip = 0;
    UnicornBackend* b = (UnicornBackend*)ctx->uc;
    if (b && b->is_64bit) {
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    } else {
        uint32_t eip = 0;
        uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        rip = eip;
    }

    printf("\n[!] Execution stopped: unmapped memory at 0x%llx (RIP=0x%llx)\n",
           (unsigned long long)address,
           (unsigned long long)rip);
    printf("    Likely an imported function/DLL jump not loaded in this emulator.\n");

    uc_emu_stop(uc);
    return false;
}

static int pe_map_image(ExecutionContext* ctx,
                        uc_engine* uc,
                        const unsigned char* file_data,
                        size_t file_len,
                        int is_64bit) {
    if (!file_data || file_len < 0x100) return -1;

    uint32_t e_lfanew = *(uint32_t*)(file_data + 60);
    if (e_lfanew + 4 + 20 > file_len) return -2;

    if (memcmp(file_data + e_lfanew, "PE\0\0", 4) != 0) return -3;

    const unsigned char* coff = file_data + e_lfanew + 4;
    uint16_t num_sections = *(uint16_t*)(coff + 2);
    uint16_t opt_header_size = *(uint16_t*)(coff + 16);

    const unsigned char* opt = coff + 20;
    if ((size_t)(opt - file_data) + opt_header_size > file_len) return -4;

    uint32_t entry_point_rva = *(uint32_t*)(opt + 16);

    uint64_t image_base = 0;
    uint32_t size_of_image = *(uint32_t*)(opt + 56);
    uint32_t size_of_headers = *(uint32_t*)(opt + 60);

    if (is_64bit) {
        image_base = *(uint64_t*)(opt + 24);
    } else {
        image_base = *(uint32_t*)(opt + 28);
    }

    ctx->image_base = image_base;
    ctx->entry_point = entry_point_rva;

    uint64_t map_size = align_up(size_of_image, PAGE_ALIGN);
    if (uc_mem_map(uc, image_base, map_size, UC_PROT_ALL) != UC_ERR_OK) {
        return -5;
    }

    // Map headers
    if (size_of_headers > 0 && size_of_headers <= file_len) {
        if (uc_mem_write(uc, image_base, file_data, size_of_headers) != UC_ERR_OK) {
            return -6;
        }
    }

    // Find .text bounds and map each section
    const unsigned char* sections = opt + opt_header_size;
    if ((size_t)(sections - file_data) + (size_t)num_sections * 40 > file_len) return -7;

    ctx->code_start = 0;
    ctx->code_end = 0;

    for (uint16_t i = 0; i < num_sections; i++) {
        const unsigned char* sec = sections + (i * 40);
        char name[9] = {0};
        memcpy(name, sec, 8);

        uint32_t virtual_size = *(uint32_t*)(sec + 8);
        uint32_t virtual_addr = *(uint32_t*)(sec + 12);
        uint32_t raw_size = *(uint32_t*)(sec + 16);
        uint32_t raw_ptr = *(uint32_t*)(sec + 20);

        uint64_t dest = image_base + virtual_addr;

        if (raw_size > 0 && raw_ptr > 0 && (uint64_t)raw_ptr + raw_size <= file_len) {
            uc_mem_write(uc, dest, file_data + raw_ptr, raw_size);
        }

        if (strncmp(name, ".text", 5) == 0) {
            ctx->code_start = image_base + virtual_addr;
            ctx->code_end = ctx->code_start + (virtual_size ? virtual_size : raw_size);
        }
    }

    return 0;
}

int decode_instruction(ExecutionContext* ctx, uint64_t address, DecodedInstruction* out) {
    // In the Unicorn backend, decoding is done in the instruction hook.
    // Keep this function for API compatibility.
    if (!ctx || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->address = address;
    strcpy(out->mnemonic, "<unicorn>");
    strcpy(out->full_text, "<unicorn backend>");
    return 0;
}

int execute_init(ExecutionContext* ctx,
                 const unsigned char* file_data,
                 size_t file_len,
                 int is_64bit) {
    if (!ctx || !file_data || file_len < 64) return -1;
    memset(ctx, 0, sizeof(*ctx));

    ctx->backend = EXEC_BACKEND_UNICORN;
    ctx->verbose = 1;

    UnicornBackend* b = calloc(1, sizeof(*b));
    if (!b) return -2;
    b->is_64bit = is_64bit ? 1 : 0;

    uc_engine* uc = NULL;
    uc_err err = uc_open(UC_ARCH_X86, is_64bit ? UC_MODE_64 : UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        free(b);
        return -3;
    }

    b->uc = uc;

    csh cs;
    if (cs_open(CS_ARCH_X86, is_64bit ? CS_MODE_64 : CS_MODE_32, &cs) != CS_ERR_OK) {
        uc_close(uc);
        free(b);
        return -4;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_OFF);
    b->cs = cs;

    // Map PE image into Unicorn memory
    int map_rc = pe_map_image(ctx, uc, file_data, file_len, is_64bit);
    if (map_rc != 0) {
        cs_close(&cs);
        uc_close(uc);
        free(b);
        return -10 + map_rc;
    }

    // Map stack
    ctx->stack_base = 0x0000000000200000ULL;
    ctx->stack_size = 2 * 1024 * 1024;
    uint64_t stack_map_size = align_up(ctx->stack_size, PAGE_ALIGN);
    if (uc_mem_map(uc, ctx->stack_base, stack_map_size, UC_PROT_ALL) != UC_ERR_OK) {
        cs_close(&cs);
        uc_close(uc);
        free(b);
        return -20;
    }

    // Initialize registers
    if (is_64bit) {
        uint64_t rip = ctx->image_base + ctx->entry_point;
        uint64_t rsp = ctx->stack_base + ctx->stack_size - 0x20;
        rsp &= ~0xFULL;
        uint64_t rbp = rsp;
        uint64_t rflags = 0x202;

        uc_reg_write(uc, UC_X86_REG_RIP, &rip);
        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
        uc_reg_write(uc, UC_X86_REG_RBP, &rbp);
        uc_reg_write(uc, UC_X86_REG_EFLAGS, &rflags);

        ctx->cpu.rip = rip;
        ctx->cpu.rsp = rsp;
        ctx->cpu.rbp = rbp;
        ctx->cpu.rflags = rflags;
    } else {
        uint32_t eip = (uint32_t)(ctx->image_base + ctx->entry_point);
        uint32_t esp = (uint32_t)(ctx->stack_base + ctx->stack_size - 0x20);
        esp &= ~0xFULL;
        uint32_t ebp = esp;
        uint32_t eflags = 0x202;

        uc_reg_write(uc, UC_X86_REG_EIP, &eip);
        uc_reg_write(uc, UC_X86_REG_ESP, &esp);
        uc_reg_write(uc, UC_X86_REG_EBP, &ebp);
        uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

        ctx->cpu.rip = eip;
        ctx->cpu.rsp = esp;
        ctx->cpu.rbp = ebp;
        ctx->cpu.rflags = eflags;
    }

    // Install hooks
    uc_hook trace_hook;
    uc_hook mem_hook;
    uc_hook_add(uc, &trace_hook, UC_HOOK_CODE, hook_code, ctx, 1, 0);
    uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_UNMAPPED, hook_mem_invalid, ctx, 1, 0);

    ctx->uc = b;
    ctx->cs = NULL;
    ctx->halted = 0;
    ctx->instruction_count = 0;

    return 0;
}

int execute_step(ExecutionContext* ctx) {
    if (!ctx) return -1;
    if (ctx->halted) return 1;

    UnicornBackend* b = (UnicornBackend*)ctx->uc;
    if (!b || !b->uc) return -2;

    uint64_t rip = 0;
    if (b->is_64bit) {
        uc_reg_read(b->uc, UC_X86_REG_RIP, &rip);
    } else {
        uint32_t eip = 0;
        uc_reg_read(b->uc, UC_X86_REG_EIP, &eip);
        rip = eip;
    }

    uc_err err = uc_emu_start(b->uc, rip, 0, 0, 1);
    if (err != UC_ERR_OK && !ctx->halted) {
        printf("\n[!] Execution stopped: %s\n", uc_strerror(err));
        ctx->halted = 1;
        return -3;
    }

    return ctx->halted ? 1 : 0;
}

size_t execute_run(ExecutionContext* ctx, size_t max_instructions) {
    if (!ctx) return 0;

    UnicornBackend* b = (UnicornBackend*)ctx->uc;
    if (!b || !b->uc) return 0;

    print_trace_header(ctx);

    // Start from current RIP
    uint64_t rip = 0;
    if (b->is_64bit) {
        uc_reg_read(b->uc, UC_X86_REG_RIP, &rip);
    } else {
        uint32_t eip = 0;
        uc_reg_read(b->uc, UC_X86_REG_EIP, &eip);
        rip = eip;
    }

    uc_err err = uc_emu_start(b->uc, rip, 0, 0, max_instructions);
    if (err != UC_ERR_OK && !ctx->halted) {
        printf("\n[!] Execution stopped: %s\n", uc_strerror(err));
        ctx->halted = 1;
    }

    // Refresh CPU state
    if (b->is_64bit) {
        uc_reg_read(b->uc, UC_X86_REG_RAX, &ctx->cpu.rax);
        uc_reg_read(b->uc, UC_X86_REG_RBX, &ctx->cpu.rbx);
        uc_reg_read(b->uc, UC_X86_REG_RCX, &ctx->cpu.rcx);
        uc_reg_read(b->uc, UC_X86_REG_RDX, &ctx->cpu.rdx);
        uc_reg_read(b->uc, UC_X86_REG_RSI, &ctx->cpu.rsi);
        uc_reg_read(b->uc, UC_X86_REG_RDI, &ctx->cpu.rdi);
        uc_reg_read(b->uc, UC_X86_REG_RBP, &ctx->cpu.rbp);
        uc_reg_read(b->uc, UC_X86_REG_RSP, &ctx->cpu.rsp);
        uc_reg_read(b->uc, UC_X86_REG_R8,  &ctx->cpu.r8);
        uc_reg_read(b->uc, UC_X86_REG_R9,  &ctx->cpu.r9);
        uc_reg_read(b->uc, UC_X86_REG_R10, &ctx->cpu.r10);
        uc_reg_read(b->uc, UC_X86_REG_R11, &ctx->cpu.r11);
        uc_reg_read(b->uc, UC_X86_REG_R12, &ctx->cpu.r12);
        uc_reg_read(b->uc, UC_X86_REG_R13, &ctx->cpu.r13);
        uc_reg_read(b->uc, UC_X86_REG_R14, &ctx->cpu.r14);
        uc_reg_read(b->uc, UC_X86_REG_R15, &ctx->cpu.r15);
        uc_reg_read(b->uc, UC_X86_REG_RIP, &ctx->cpu.rip);
        uc_reg_read(b->uc, UC_X86_REG_EFLAGS, &ctx->cpu.rflags);
    } else {
        uint32_t tmp = 0;
        uc_reg_read(b->uc, UC_X86_REG_EAX, &tmp); ctx->cpu.rax = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EBX, &tmp); ctx->cpu.rbx = tmp;
        uc_reg_read(b->uc, UC_X86_REG_ECX, &tmp); ctx->cpu.rcx = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EDX, &tmp); ctx->cpu.rdx = tmp;
        uc_reg_read(b->uc, UC_X86_REG_ESI, &tmp); ctx->cpu.rsi = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EDI, &tmp); ctx->cpu.rdi = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EBP, &tmp); ctx->cpu.rbp = tmp;
        uc_reg_read(b->uc, UC_X86_REG_ESP, &tmp); ctx->cpu.rsp = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EIP, &tmp); ctx->cpu.rip = tmp;
        uc_reg_read(b->uc, UC_X86_REG_EFLAGS, &tmp); ctx->cpu.rflags = tmp;
    }

    printf("\n──────────────────────────────────────────────────────────────────\n");
    printf("Execution %s after %zu instructions\n",
           ctx->halted ? "halted" : "paused (limit reached)",
           (size_t)ctx->instruction_count);
    printf("══════════════════════════════════════════════════════════════════\n");

    return (size_t)ctx->instruction_count;
}

void print_instruction(const DecodedInstruction* instr) {
    // Not used in Unicorn backend (printing happens in hook)
    if (!instr) return;
    printf("0x%08llx │ <unicorn> │ %s\n", (unsigned long long)instr->address, instr->full_text);
}

void print_cpu_state(const CPUState* cpu, int is_64bit) {
    // Reuse the pretty printer from the simple backend by duplicating minimal output here.
    // Keep format stable.
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
        printf("│ RIP: %016llx  RFLAGS: %016llx │\n",
               (unsigned long long)cpu->rip, (unsigned long long)cpu->rflags);
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
        printf("│ EIP: %08llx  EFLAGS: %08llx │\n",
               (unsigned long long)(cpu->rip & 0xFFFFFFFF),
               (unsigned long long)(cpu->rflags & 0xFFFFFFFF));
    }

    printf("└─────────────────────────────────────────────────────────────┘\n");
}

void execute_cleanup(ExecutionContext* ctx) {
    if (!ctx) return;

    UnicornBackend* b = (UnicornBackend*)ctx->uc;
    if (b) {
        if (b->cs) {
            cs_close(&b->cs);
        }
        if (b->uc) {
            uc_close(b->uc);
        }
        free(b);
    }

    ctx->uc = NULL;
    ctx->cs = NULL;
    ctx->halted = 1;
}

void format_instruction(const DecodedInstruction* instr, char* buffer, size_t buffer_size) {
    if (!instr || !buffer || buffer_size == 0) return;
    snprintf(buffer, buffer_size, "0x%08llx: %s",
             (unsigned long long)instr->address,
             instr->full_text);
}
