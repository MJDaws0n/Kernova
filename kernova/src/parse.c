// parse.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "parse.h"

struct File {
    char* path;
    int length;

    char* IMAGE_DOS_HEADER;
    int e_lfanew;
    char* DOS_stub;
    char* PE_signature;
    char* COFF_header;
    int OptionalHeaderSize;
};

typedef struct {
    char* data;
    size_t length;
} ByteData;

static int file_exists(const char* filename);
static ByteData get_byte_data(const char* file);
static char* bytes_to_hex(const unsigned char* data, size_t len);
static char* get_IMAGE_DOS_HEADER(const char* data);
static char* get_DOS_stub(const char* data, int offset);
static char* get_PE_signature(const char* data, int offset);
static char* get_COFF_header(const char* data, int offset);
static unsigned int get_e_lfanew(const char* data);

/**
 * Begins to parse the executable file
 * @param file The directory of the file to parse
 * @return int exit code
 */
void parse(const char* file) {
    struct File f;
    printf("Attempting to parse %s...\n", file);
    
    // Check if file exists
    debug_print("Debug: Checking if file exists...\n");
    if (!file_exists(file)) {
        fprintf(stderr, "Error: File %s does not exist.\n", file);
        return;
    }

    // Begin parsing
    debug_print("Debug: File exists. Reading byte data...\n");
    ByteData p = get_byte_data(file);
    if (!p.data) {
        fprintf(stderr, "Error: Failed to read byte data from %s\n", file);
        return;
    }
    debug_print("Debug: Successfully read byte data from %s\n", file);
    printf("Byte data read. Beginning parsing...\n");

    debug_print("Extracting IMAGE_DOS_HEADER...\n");
    f.IMAGE_DOS_HEADER = get_IMAGE_DOS_HEADER(p.data);
    f.e_lfanew = get_e_lfanew(f.IMAGE_DOS_HEADER);

    f.DOS_stub = get_DOS_stub(p.data, f.e_lfanew);
    f.PE_signature = get_PE_signature(p.data, f.e_lfanew);

    f.COFF_header = get_COFF_header(p.data, f.e_lfanew);
    f.OptionalHeaderSize = (unsigned char)f.COFF_header[16] | ((unsigned char)f.COFF_header[17] << 8);

    printf(f.OptionalHeaderSize == 224 ? "Executable is 32 bit\n" : f.OptionalHeaderSize == 240 ? "Executable is 64 bit\n" : "Unknown PE format\n");

    printf("%s\n", bytes_to_hex(f.PE_signature, 4));
}

/**
 * Check if a file exists
 * @param filename The name of the file to check
 * @return int 1 if exists, 0 otherwise
 */
static int file_exists(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (f) {
        fclose(f);
        return 1; // file exists
    }
    return 0; // file does not exist
}

/**
 * Get byte data from file
 * @param file The file to read from
 * @return char* byte data (raw, not hex-encoded)
 */
static ByteData get_byte_data(const char* file) {
    ByteData result = { NULL, 0 };
    FILE* f = fopen(file, "rb");
    if (!f) return result;

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (filesize <= 0) {
        fclose(f);
        return result;
    }

    result.data = malloc(filesize);
    if (!result.data) {
        fclose(f);
        return result;
    }

    size_t read_bytes = fread(result.data, 1, filesize, f);
    fclose(f);

    if (read_bytes != filesize) {
        free(result.data);
        result.data = NULL;
        return result;
    }

    result.length = read_bytes;
    return result;
}

/**
 * Returns the IMAGE_DOS_HEADER from the byte data
 * @param file The file to read from
 * @return char* byte data
 */
static char* get_IMAGE_DOS_HEADER(const char* data) {
    if (!data) return NULL;

    // Allocate bytes
    char* header = malloc(64);
    if (!header) return NULL;

    // Copy from the buffer
    memcpy(header, data, 64);

    return header;
}

/**
 * Returns the e_lfanew field from the IMAGE_DOS_HEADER as an int
 * @param data The data to read from
 * @return e_lfanew as an unsigned int
 */
static unsigned int get_e_lfanew(const char* data) {
    if (!data) return 0;

    // Read 4 bytes at offset 60 (little-endian)
    return (unsigned char)data[60]       |
           ((unsigned char)data[61] << 8)  |
           ((unsigned char)data[62] << 16) |
           ((unsigned char)data[63] << 24);
}

/**
 * Returns the DOS Stub from the byte data
 * @param file The file to read from
 * @param offset The offset to start reading from
 * @return char* byte data
 */
static char* get_DOS_stub(const char* data, int offset) {
    if (!data || offset <= 64) return NULL;

    unsigned int stub_size = offset - 64;
    char* stub = malloc(stub_size);
    if (!stub) return NULL;

    memcpy(stub, data + 64, stub_size);

    return stub;
}

/**
 * Returns the PE Signature from the byte data
 * @param file The file to read from
 * @param offset The offset to start reading from
 * @return char* byte data
 */
static char* get_PE_signature(const char* data, int offset) {
    if (!data || offset < 64) return NULL;

    char* pe_sig = malloc(4);
    if (!pe_sig) return NULL;

    memcpy(pe_sig, data + offset, 4);

    return pe_sig;
}

/**
 * Returns the COFF Header from the byte data
 * @param file The file to read from
 * @param offset The offset to start reading from
 * @return char* byte data
 */
static char* get_COFF_header(const char* data, int offset) {
    if (!data || offset < 64) return NULL;

    char* coff_header = malloc(20);
    if (!coff_header) return NULL;

    memcpy(coff_header, data + offset + 4, 20);

    return coff_header;
}

/**
 * Converts a byte buffer to a hex string
 * @param data The byte buffer
 * @param len The length of the byte buffer
 * @return A malloc'd string containing hex (caller must free)
 */
static char* bytes_to_hex(const unsigned char* data, size_t len) {
    if (!data || len == 0) return NULL;

    char* hex = malloc(len * 2 + 1); // 2 chars per byte + null terminator
    if (!hex) return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i*2, "%02X", data[i]);
    }

    hex[len*2] = '\0';
    return hex;
}