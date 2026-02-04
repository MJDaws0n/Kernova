// parse_sections.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "main.h"
#include "parse.h"
#include "parse_sections.h"

// --- Internal helpers ------------------------------------------------------
static SectionHeader parse_section_header(const char* section_bytes);
static int is_target_section_name(const char* name);
static SectionObject* ensure_section_object(SectionSet* set, const SectionHeader* sh);
static int enumerate_section_raw(const unsigned char* file_data, size_t file_len,
                                 SectionObject* obj, int enum_mode);

// --- Parsing of raw 40-byte section header ---------------------------------
static SectionHeader parse_section_header(const char* section) {
    SectionHeader sh = (SectionHeader){0};
    if (!section) return sh;

    memcpy(sh.Name, section, 8);
    sh.Name[8] = '\0';

    sh.VirtualSize          = *(uint32_t*)(section + 8);
    sh.VirtualAddress       = *(uint32_t*)(section + 12);
    sh.SizeOfRawData        = *(uint32_t*)(section + 16);
    sh.PointerToRawData     = *(uint32_t*)(section + 20);
    sh.PointerToRelocations = *(uint32_t*)(section + 24);
    sh.PointerToLineNumbers = *(uint32_t*)(section + 28);
    sh.NumberOfRelocations  = *(uint16_t*)(section + 32);
    sh.NumberOfLineNumbers  = *(uint16_t*)(section + 34);
    sh.Characteristics      = *(uint32_t*)(section + 36);
    return sh;
}

// Return 1 if this is one of the sections we want to collect (.data, .rdata, .pdata)
static int is_target_section_name(const char* name) {
    if (!name) return 0;
    // Names in PE section table may omit leading dot if padded; handle both.
    if (strncmp(name, ".data", 8) == 0 || strncmp(name, "data", 8) == 0) return 1;
    if (strncmp(name, ".rdata", 8) == 0 || strncmp(name, "rdata", 8) == 0) return 1;
    if (strncmp(name, ".pdata", 8) == 0 || strncmp(name, "pdata", 8) == 0) return 1;
    return 0;
}

// Grow/allocate a SectionObject for a target section header.
static SectionObject* ensure_section_object(SectionSet* set, const SectionHeader* sh) {
    if (!set || !sh) return NULL;
    // Check if it already exists (shouldn't normally because names are unique)
    for (size_t i = 0; i < set->count; ++i) {
        if (strncmp(set->sections[i].name, sh->Name, 8) == 0) {
            return &set->sections[i];
        }
    }
    // Allocate new slot
    SectionObject* new_arr = realloc(set->sections, (set->count + 1) * sizeof(SectionObject));
    if (!new_arr) return NULL;
    set->sections = new_arr;
    SectionObject* obj = &set->sections[set->count];
    memset(obj, 0, sizeof(*obj));
    memcpy(obj->name, sh->Name, 9);
    obj->header = *sh;
    obj->vars = NULL;
    obj->var_count = 0;
    obj->var_capacity = 0;
    set->count++;
    return obj;
}

// --- Public legacy function (unchanged external behavior) ------------------
void parse_sections(const char* sections) {
    debug_print("Parsing sections (legacy)...\n");
    if (!sections) return;
    // Commented out: Spammy section header output for each section
    // This was printing detailed info for every section which clutters the console
    /*
    for (int i = 0; i < 5; i++) { // Legacy fixed count
        SectionHeader sh = parse_section_header(sections + (i * 40));
        print_section_header(&sh);
    }
    */
}

// --- New API Implementation ------------------------------------------------
int parse_sections_collect(const char* sections, int number_of_sections, SectionSet* out) {
    if (!sections || number_of_sections <= 0 || !out) return -1;
    out->sections = NULL;
    out->count = 0;

    for (int i = 0; i < number_of_sections; ++i) {
        const char* base = sections + (i * 40);
        SectionHeader sh = parse_section_header(base);
        if (is_target_section_name(sh.Name)) {
            SectionObject* obj = ensure_section_object(out, &sh);
            if (!obj) {
                section_set_free(out);
                return -2; // allocation failure
            }
            // Populate with some default interesting variables from header
            section_object_add_var(obj, "VirtualSize", sh.VirtualSize);
            section_object_add_var(obj, "VirtualAddress", sh.VirtualAddress);
            section_object_add_var(obj, "SizeOfRawData", sh.SizeOfRawData);
            section_object_add_var(obj, "PointerToRawData", sh.PointerToRawData);
            section_object_add_var(obj, "Characteristics", sh.Characteristics);
        }
    }
    return 0;
}

int section_object_add_var(SectionObject* obj, const char* name, uint64_t value) {
    if (!obj || !name) return -1;
    if (obj->var_count == obj->var_capacity) {
        size_t new_cap = obj->var_capacity == 0 ? 4 : obj->var_capacity * 2;
        SectionVariable* new_vars = realloc(obj->vars, new_cap * sizeof(SectionVariable));
        if (!new_vars) return -2;
        obj->vars = new_vars;
        obj->var_capacity = new_cap;
    }
    SectionVariable* v = &obj->vars[obj->var_count++];
    v->value = value;
    size_t len = strlen(name);
    v->name = malloc(len + 1);
    if (!v->name) return -3;
    memcpy(v->name, name, len + 1);
    return 0;
}

void section_object_free(SectionObject* obj) {
    if (!obj) return;
    for (size_t i = 0; i < obj->var_count; ++i) {
        free(obj->vars[i].name);
    }
    free(obj->vars);
    obj->vars = NULL;
    obj->var_count = obj->var_capacity = 0;
}

void section_set_free(SectionSet* set) {
    if (!set) return;
    for (size_t i = 0; i < set->count; ++i) {
        section_object_free(&set->sections[i]);
    }
    free(set->sections);
    set->sections = NULL;
    set->count = 0;
}

// --- Printing helpers ------------------------------------------------------
void print_section_header(const SectionHeader* sh) {
    if (!sh) return;
    printf("Name: %s\n", sh->Name);
    printf("  VirtualSize: 0x%X\n", sh->VirtualSize);
    printf("  VirtualAddress: 0x%X\n", sh->VirtualAddress);
    printf("  SizeOfRawData: 0x%X\n", sh->SizeOfRawData);
    printf("  PointerToRawData: 0x%X\n", sh->PointerToRawData);
    printf("  PointerToRelocations: 0x%X\n", sh->PointerToRelocations);
    printf("  PointerToLineNumbers: 0x%X\n", sh->PointerToLineNumbers);
    printf("  NumberOfRelocations: %u\n", sh->NumberOfRelocations);
    printf("  NumberOfLineNumbers: %u\n", sh->NumberOfLineNumbers);
    printf("  Characteristics: 0x%X\n", sh->Characteristics);
}

void print_section_object(const SectionObject* obj) {
    if (!obj) return;
    print_section_header(&obj->header);
    if (obj->var_count == 0) {
        printf("  (no variables)\n");
        return;
    }
    printf("  Variables (%zu):\n", obj->var_count);
    for (size_t i = 0; i < obj->var_count; ++i) {
        printf("    %s = 0x%llX\n", obj->vars[i].name, (unsigned long long)obj->vars[i].value);
    }
}

int parse_sections_collect_with_data(const char* sections,
                                     int number_of_sections,
                                     const unsigned char* file_data,
                                     size_t file_len,
                                     int enum_mode,
                                     SectionSet* out) {
    int rc = parse_sections_collect(sections, number_of_sections, out);
    if (rc != 0) return rc;
    // Now enumerate raw bytes/dwords into variables for each collected section
    for (size_t i = 0; i < out->count; ++i) {
        enumerate_section_raw(file_data, file_len, &out->sections[i], enum_mode);
    }
    return 0;
}

void print_section_object_data(const SectionObject* obj) {
    if (!obj) return;
    printf("%s data variables (%zu):\n", obj->name, obj->var_count);
    for (size_t i = 0; i < obj->var_count; ++i) {
        printf("  %s: 0x%llX\n", obj->vars[i].name, (unsigned long long)obj->vars[i].value);
    }
}

void print_section_object_json(const SectionObject* obj) {
    if (!obj) return;
    printf("{\n");
    printf("  \"name\": \"%s\",\n", obj->name);
    printf("  \"header\": { \"VirtualSize\": %u, \"VirtualAddress\": %u, \"SizeOfRawData\": %u, \"PointerToRawData\": %u, \"Characteristics\": %u },\n",
           obj->header.VirtualSize, obj->header.VirtualAddress, obj->header.SizeOfRawData,
           obj->header.PointerToRawData, obj->header.Characteristics);
    printf("  \"variables\": [\n");
    for (size_t i = 0; i < obj->var_count; ++i) {
        printf("    { \"name\": \"%s\", \"value\": %llu }%s\n", obj->vars[i].name,
               (unsigned long long)obj->vars[i].value, (i + 1 == obj->var_count) ? "" : ",");
    }
    printf("  ]\n");
    printf("}\n");
}

void print_section_set_json(const SectionSet* set) {
    if (!set) return;
    printf("[\n");
    for (size_t i = 0; i < set->count; ++i) {
        print_section_object_json(&set->sections[i]);
        if (i + 1 < set->count) printf(",\n");
    }
    printf("\n]\n");
}

// ---------------------------------------------------------------------------
// Raw data enumeration
// ---------------------------------------------------------------------------
static int enumerate_section_raw(const unsigned char* file_data, size_t file_len,
                                 SectionObject* obj, int enum_mode) {
    if (!file_data || !obj) return -1;
    const SectionHeader* h = &obj->header;
    if (h->PointerToRawData + h->SizeOfRawData > file_len) return -2;
    const unsigned char* raw = file_data + h->PointerToRawData;

    if (enum_mode == SECTION_ENUM_DWORDS) {
        // group every 4 bytes (little-endian)
        for (uint32_t off = 0; off + 4 <= h->SizeOfRawData; off += 4) {
            uint32_t val = *(uint32_t*)(raw + off);
            char name[32];
            snprintf(name, sizeof(name), "dword_0x%X", h->PointerToRawData + off);
            if (section_object_add_var(obj, name, val) != 0) return -3;
        }
    } else { // default to bytes
        for (uint32_t off = 0; off < h->SizeOfRawData; ++off) {
            unsigned char b = raw[off];
            char name[32];
            snprintf(name, sizeof(name), "byte_0x%X", h->PointerToRawData + off);
            if (section_object_add_var(obj, name, b) != 0) return -4;
        }
    }
    return 0;
}