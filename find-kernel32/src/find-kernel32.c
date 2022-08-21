#include "find-kernel32.h"
//#include <stdio.h>

_LoadLibraryA *fLoadLibraryA = NULL;
_GetProcAddress *fGetProcAddress = NULL;

VOID FindKernel32(VOID)
{
    PPEB peb = (PPEB)__readgsqword(TEB_PPEB_OFFSET64);

    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;

    PLIST_ENTRY ldrListEntry = listHead->Flink;

    PLDR_DATA_TABLE_ENTRY ldrEntry = NULL;

    while (ldrListEntry != listHead) {
        ldrEntry = CONTAINING_RECORD(ldrListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                                //LDR_DATA_TABLE_ENTRY->BaseDllName isnt defined in winternl.h
        PUNICODE_STRING dllName = (PUNICODE_STRING)&ldrEntry->Reserved4;

        DWORD64 hash = HashString(dllName->Buffer, 2);

        //wprintf(L"%ls 0x%llx\n", dllName->Buffer, hash);

        if (hash == HASH_KERNEL32) {
            break;
        }
        
        ldrListEntry = ldrListEntry->Flink;
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)ldrEntry->DllBase;

    PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDOSHeader + pDOSHeader->e_lfanew);

    PIMAGE_OPTIONAL_HEADER64 pOptHeader = &pNTHeader->OptionalHeader;

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDOSHeader + pExportDataDir->VirtualAddress);

    PDWORD exportNamesRVA = (PDWORD)((PBYTE)pDOSHeader + pExportDir->AddressOfNames);
    PDWORD exportAddrRVA = (PDWORD)((PBYTE)pDOSHeader + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {

        LPSTR exportName = (LPSTR)((PBYTE)pDOSHeader + exportNamesRVA[i]);

        DWORD64 hash = HashString(exportName, 1);

        //printf("%s 0x%llx\n", exportName, hash);

        if (hash == HASH_LOAD_LIB) {
            fLoadLibraryA = (PVOID)((PBYTE)pDOSHeader + exportAddrRVA[i]);
        }

        else if (hash == HASH_GET_PROC) {
            fGetProcAddress = (PVOID)((PBYTE)pDOSHeader + exportAddrRVA[i]);
        }
    }
}

PVOID LocateFunction(LPSTR module, LPSTR function) {
    return fGetProcAddress( fLoadLibraryA(module), function );
}

DWORD64 HashString(PVOID buff, INT charSize) {
    // https://stackoverflow.com/questions/14409466/simple-hash-functions

    DWORD64 hash = 1234;

    if (charSize == 1) {
        LPSTR cBuff = buff;
        
        while (*cBuff != 0) {
            hash = ((hash << 5) + hash) + *cBuff;
            cBuff++;
        }
    }

    else if (charSize == 2) {
        LPWSTR wBuff = buff;

        while (*wBuff != 0) {
            hash = ((hash << 5) + hash) + *wBuff;
            wBuff++;
        }
    }

    return hash;
}