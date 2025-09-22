# Kernova
https://mjdawson.net/projects/kernova
Currently can determine if file is 64 or 32 bit

# Build and run with
make -C ./kernova && ./kernova/build/kernova_bin example.exe

## Header infomation
1.	DOS Header → file_bytes[0:64]
2.	DOS Stub → file_bytes[64:e_lfanew]
3.	PE Signature → file_bytes[e_lfanew:e_lfanew+4]
4.	COFF Header → file_bytes[e_lfanew+4:e_lfanew+24]
5.	Optional Header → file_bytes[e_lfanew+24:e_lfanew+24+OptionalHeaderSize]
6.	Section Headers → file_bytes[e_lfanew+24+OptionalHeaderSize: …]