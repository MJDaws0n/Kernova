#ifndef PARSE_SECTIONS_H
#define PARSE_SECTIONS_H

#include <stdint.h>
#include <stddef.h>

// Public representation of a PE section header (40 bytes on disk)
typedef struct {
	char     Name[9];              // 8 chars + null terminator
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

// A simple name/value pair extracted/logically belonging to a section.
// Value kept as 64-bit to allow addresses, sizes, etc.
typedef struct {
	char*    name;     // heap-allocated copy of the reference name
	uint64_t value;    // numeric value (address, size, RVA, etc.)
} SectionVariable;

// Container for one target section (e.g. .data, .rdata, .pdata) holding
// its header plus an expandable list of variables.
typedef struct {
	char            name[9];   // cached header name for quick access
	SectionHeader   header;    // original parsed header
	SectionVariable *vars;     // dynamic array of variables
	size_t          var_count; // number of used entries
	size_t          var_capacity; // allocated capacity
} SectionObject;

// Set of collected target sections.
typedef struct {
	SectionObject *sections; // dynamic array
	size_t         count;    // number of collected sections
} SectionSet;

// Legacy printer-style parse (kept for backward compatibility)
void parse_sections(const char* sections);

// New API: parse all section headers and collect data for target sections
// (.data, .rdata, .pdata). Returns 0 on success, non-zero on allocation error.
int parse_sections_collect(const char* sections, int number_of_sections, SectionSet* out);

// Enumeration modes for raw section data -> variables
#define SECTION_ENUM_BYTES  1
#define SECTION_ENUM_DWORDS 2

// Collect and ALSO enumerate raw data from each target section into per-byte or per-dword
// SectionVariable entries (names like byte_0xOFFSET or dword_0xOFFSET). Returns 0 on success.
int parse_sections_collect_with_data(const char* sections,
									 int number_of_sections,
									 const unsigned char* file_data,
									 size_t file_len,
									 int enum_mode,
									 SectionSet* out);

// Add a variable to a SectionObject. Returns 0 on success.
int section_object_add_var(SectionObject* obj, const char* name, uint64_t value);

// Free helpers
void section_object_free(SectionObject* obj);
void section_set_free(SectionSet* set);

// Debug/printing helpers
void print_section_header(const SectionHeader* sh);
void print_section_object(const SectionObject* obj);
void print_section_object_data(const SectionObject* obj); // raw data vars only
void print_section_object_json(const SectionObject* obj); // JSON-like output (header + vars)
void print_section_set_json(const SectionSet* set);       // JSON-like output for whole set

#endif