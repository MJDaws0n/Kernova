// kernova.c
#include <stdio.h>
#include <stdarg.h>
#include "startup.h"
#include "main.h"
#include "parse.h"

char* version = "v0.2 (Execution Engine)";
int debug = 0;  // Set to 0 to reduce console spam - only show instruction execution

/**
 * Main function
 * @param argc Argument count
 * @param argv Argument vector
 * @return int exit code
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    startup(version);
    parse(argv[1]);
    return 0;
}

/**
 * Debug print function
 * @param fmt The format string
 * @param ... Arguments for the format
 * @return void
 */
void debug_print(const char* fmt, ...) {
    if (debug) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}