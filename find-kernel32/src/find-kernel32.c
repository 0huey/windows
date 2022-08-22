#include "find-kernel32.h"

PLOAD_LIBRARY_A fLoadLibraryA = NULL;
PGET_PROC_ADDRESS fGetProcAddress = NULL;

VOID FindKernel32(VOID)
{
    PPEB peb = (PPEB)__readgsqword(TEB_PPEB_OFFSET64);

    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;

    PLIST_ENTRY ldrListEntry = listHead->Flink;

    PBYTE kernel32Base = NULL;

    while (ldrListEntry != listHead) {
        PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(ldrListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                                //LDR_DATA_TABLE_ENTRY::BaseDllName isnt defined in winternl.h
        PUNICODE_STRING dllName = (PUNICODE_STRING)&ldrEntry->Reserved4;

        if (HashString(dllName->Buffer, sizeof(WCHAR)) == HASH_KERNEL32) {
            kernel32Base = ldrEntry->DllBase;
            break;
        }
        
        ldrListEntry = ldrListEntry->Flink;
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)kernel32Base;

    PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)(kernel32Base + pDOSHeader->e_lfanew);

    PIMAGE_OPTIONAL_HEADER64 pOptHeader = &pNTHeader->OptionalHeader;

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(kernel32Base + pExportDataDir->VirtualAddress);

    PDWORD exportNamesRVA = (PDWORD)(kernel32Base + pExportDir->AddressOfNames);
    PDWORD exportAddrRVA  = (PDWORD)(kernel32Base + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {

        LPSTR exportName = (LPSTR)(kernel32Base + exportNamesRVA[i]);

        DWORD64 hash = HashString(exportName, sizeof(CHAR));

        if (hash == HASH_LOAD_LIB) {
            fLoadLibraryA = (PVOID)(kernel32Base + exportAddrRVA[i]);
        }

        else if (hash == HASH_GET_PROC) {
            fGetProcAddress = (PVOID)(kernel32Base + exportAddrRVA[i]);
        }
    }
}

PVOID LocateFunction(LPCSTR module, LPCSTR function) {
    return fGetProcAddress( fLoadLibraryA(module), function );
}

DWORD64 HashString(PVOID buff, INT charWidth) {
    // https://stackoverflow.com/questions/14409466/simple-hash-functions

    DWORD64 hash = 1234;

    if (charWidth == sizeof(CHAR)) {
        LPSTR cBuff = buff;
        
        while (*cBuff != 0) {
            hash = ((hash << 5) + hash) + *cBuff;
            cBuff++;
        }
    }

    else if (charWidth == sizeof(WCHAR)) {
        LPWSTR wBuff = buff;

        while (*wBuff != 0) {
            hash = ((hash << 5) + hash) + *wBuff;
            wBuff++;
        }
    }

    return hash;
}
