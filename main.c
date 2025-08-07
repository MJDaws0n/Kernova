#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

// PE info holder
typedef struct {
    DWORD     entry_point;
    ULONGLONG image_base;
    WORD      number_of_sections;
} PE_INFO;

// Step 1: Parse DOS + NT headers
bool parse_pe(const char *path, PE_INFO *info, IMAGE_NT_HEADERS64 **nt_out, BYTE **file_base_out) {
    FILE *f = fopen(path, "rb"); if (!f) { perror("fopen"); return false; }

    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Not a valid MZ exe\n"); fclose(f); return false;
    }
    fseek(f, dos.e_lfanew, SEEK_SET);

    IMAGE_NT_HEADERS64 *nt = malloc(sizeof(IMAGE_NT_HEADERS64));
    if (fread(nt, sizeof(*nt), 1, f) != 1 || nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Invalid PE signature\n"); fclose(f); free(nt); return false;
    }
    fclose(f);

    // Map file for imports
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { perror("CreateFile"); free(nt); return false; }
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { perror("CreateFileMapping"); CloseHandle(hFile); free(nt); return false; }
    BYTE *fileBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) { perror("MapViewOfFile"); CloseHandle(hMap); CloseHandle(hFile); free(nt); return false; }

    info->entry_point        = nt->OptionalHeader.AddressOfEntryPoint;
    info->image_base         = nt->OptionalHeader.ImageBase;
    info->number_of_sections = nt->FileHeader.NumberOfSections;

    *nt_out = nt;
    *file_base_out = fileBase;
    return true;
}

// Step 2: Map headers + sections into memory
BYTE *map_image(IMAGE_NT_HEADERS64 *nt, BYTE *fileBase) {
    SIZE_T sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    SIZE_T sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    WORD   numSections   = nt->FileHeader.NumberOfSections;

    // Allocate at preferred base or fallback
    BYTE *imageBase = VirtualAlloc((LPVOID)nt->OptionalHeader.ImageBase,
                                   sizeOfImage,
                                   MEM_RESERVE|MEM_COMMIT,
                                   PAGE_READWRITE);
    if (!imageBase) {
        imageBase = VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        if (!imageBase) { perror("VirtualAlloc"); return NULL; }
    }

    // Copy headers
    memcpy(imageBase, fileBase, sizeOfHeaders);

    // Copy sections
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < numSections; i++) {
        BYTE *dest = imageBase + section[i].VirtualAddress;
        BYTE *src  = fileBase + section[i].PointerToRawData;
        SIZE_T raw = section[i].SizeOfRawData;
        SIZE_T virt= section[i].Misc.VirtualSize;
        memcpy(dest, src, raw);
        if (virt > raw) memset(dest + raw, 0, virt - raw);
        section++;
    }

    return imageBase;
}

// Step 3: Set memory protections based on section characteristics
bool protect_sections(IMAGE_NT_HEADERS64 *nt, BYTE *imageBase) {
    WORD   numSections = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < numSections; i++) {
        DWORD protect = 0;
        BOOL  exec = section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
        BOOL  read = section[i].Characteristics & IMAGE_SCN_MEM_READ;
        BOOL  write = section[i].Characteristics & IMAGE_SCN_MEM_WRITE;
        if (exec) {
            if (write) protect = PAGE_EXECUTE_READWRITE;
            else protect = PAGE_EXECUTE_READ;
        } else {
            if (write) protect = PAGE_READWRITE;
            else protect = PAGE_READONLY;
        }
        DWORD old;
        VirtualProtect(imageBase + section[i].VirtualAddress,
                       section[i].Misc.VirtualSize,
                       protect, &old);
        section++;
    }
    return true;
}

// Step 4: Resolve imports and install logging thunks
bool resolve_imports(IMAGE_NT_HEADERS64 *nt, BYTE *imageBase, BYTE *fileBase) {
    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) return true;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + importDir.VirtualAddress);
    for (; imp->Name; imp++) {
        char *dllName = (char*)(imageBase + imp->Name);
        HMODULE hMod = LoadLibraryA(dllName);
        printf("Loaded DLL: %s -> %p\n", dllName, hMod);

        IMAGE_THUNK_DATA64 *orig = (IMAGE_THUNK_DATA64*)(fileBase + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64*)(imageBase + imp->FirstThunk);
        for (; orig->u1.AddressOfData; orig++, thunk++) {
            char *funcName;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                funcName = "Ordinal";
            } else {
                IMAGE_IMPORT_BY_NAME * ibn = (IMAGE_IMPORT_BY_NAME*)(fileBase + orig->u1.AddressOfData);
                funcName = (char*)ibn->Name;
            }
            FARPROC realAddr = GetProcAddress(hMod, funcName);
            if (!realAddr) continue;
            printf("Resolving %s -> %p\n", funcName, realAddr);

            // Build thunk: prints function name via puts, then jumps to realAddr
            size_t nameLen = strlen(funcName) + 1;
            size_t stubSize = 64;
            BYTE *stub = VirtualAlloc(NULL, stubSize + nameLen,
                                      MEM_COMMIT|MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
            BYTE *nameMem = stub + stubSize;
            memcpy(nameMem, funcName, nameLen);

            BYTE *p = stub;
            // mov rax, nameMem
            *p++ = 0x48; *p++ = 0xB8;
            *((uint64_t*)p) = (uint64_t)nameMem; p += 8;
            // mov rcx, rax
            *p++ = 0x48; *p++ = 0x89; *p++ = 0xC1;
            // mov rax, puts
            *p++ = 0x48; *p++ = 0xB8;
            *((uint64_t*)p) = (uint64_t)puts; p += 8;
            // call rax
            *p++ = 0xFF; *p++ = 0xD0;
            // mov rax, realAddr
            *p++ = 0x48; *p++ = 0xB8;
            *((uint64_t*)p) = (uint64_t)realAddr; p += 8;
            // jmp rax
            *p++ = 0xFF; *p++ = 0xE0;

            // Patch IAT
            thunk->u1.Function = (ULONGLONG)stub;
        }
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }

    PE_INFO info;
    IMAGE_NT_HEADERS64 *nt;
    BYTE *fileBase;
    if (!parse_pe(argv[1], &info, &nt, &fileBase)) return 1;
    printf("Parsed PE: Base=0x%llx, EntryRVA=0x%08x, Sections=%u\n",
           info.image_base, info.entry_point, info.number_of_sections);

    BYTE *base = map_image(nt, fileBase);
    if (!base) return 1;
    printf("Image mapped at %p\n", base);

    protect_sections(nt, base);
    resolve_imports(nt, base, fileBase);

    // Jump to entry point
    void (*entry)() = (void(*)())(base + info.entry_point);
    printf("Transferring control to entry point...\n");
    entry();

    return 0;
}

/* Compile with:
   gcc main.c -o kernova.exe
*/
