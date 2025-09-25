// parse.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "parse.h"

typedef struct {
    char     Name[9];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLineNumbers;
    uint32_t Characteristics;
} SectionHeader;

static SectionHeader parse_section(const char* section);
void print_section(const SectionHeader* sh);

SectionHeader parse_section(const char* section) {
    SectionHeader sh = {0};

    if (!section) return sh;

    memcpy(sh.Name, section, 8);
    sh.Name[8] = '\0';  // null-terminate

    sh.VirtualSize       = *(uint32_t*)(section + 8);
    sh.VirtualAddress    = *(uint32_t*)(section + 12);
    sh.SizeOfRawData     = *(uint32_t*)(section + 16);
    sh.PointerToRawData  = *(uint32_t*)(section + 20);
    sh.PointerToRelocations = *(uint32_t*)(section + 24);
    sh.PointerToLineNumbers = *(uint32_t*)(section + 28);
    sh.NumberOfRelocations   = *(uint16_t*)(section + 32);
    sh.NumberOfLineNumbers   = *(uint16_t*)(section + 34);
    sh.Characteristics       = *(uint32_t*)(section + 36);

    return sh;
}

void parse_sections(const char* sections) {
    debug_print("Parsing sections...\n");

    for (int i = 0; i < 5; i++) {
        SectionHeader sh = parse_section(sections + (i * 40));
        print_section(&sh);
    }
}

void print_section(const SectionHeader* sh) {
    if (!sh) return;

    printf("Name: %s\n", sh->Name);
    printf("VirtualSize: 0x%X\n", sh->VirtualSize);
    printf("VirtualAddress: 0x%X\n", sh->VirtualAddress);
    printf("SizeOfRawData: 0x%X\n", sh->SizeOfRawData);
    printf("PointerToRawData: 0x%X\n", sh->PointerToRawData);
    printf("PointerToRelocations: 0x%X\n", sh->PointerToRelocations);
    printf("PointerToLineNumbers: 0x%X\n", sh->PointerToLineNumbers);
    printf("NumberOfRelocations: %u\n", sh->NumberOfRelocations);
    printf("NumberOfLineNumbers: %u\n", sh->NumberOfLineNumbers);
    printf("Characteristics: 0x%X\n", sh->Characteristics);
}