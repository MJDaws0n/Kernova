// startup.c
#include <stdio.h>
#include "startup.h"
#include "main.h"

static char* system_info();

/**
 * Startup function to print version infomation
 * @param version The version string
 * @return void
 */
void startup(const char* version) {
    // System and version info
    printf("Kernova version %s\n", version);
    printf("System: %s\n", system_info());
    debug_print("Debug mode is Enabled\n");
}

/**
 * System infomation
 * @return char* OS name and version
 */
static char* system_info() {
    #if defined(_WIN32)
        return "Windows";
    #elif defined(__APPLE__)
        return "macOS";
    #elif defined(__linux__)
        return "Linux";
    #else
        debug_print("Debug: Unknown OS detected\n");
        return "Unknown OS";
    #endif
}