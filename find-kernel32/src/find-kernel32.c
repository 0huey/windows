#include "find-kernel32.h"

PLOAD_LIBRARY_A loadLibraryA = NULL;
PGET_PROC_ADDRESS getProcAddress = NULL;

VOID FindKernel32(VOID) {
    PPEB peb = (PPEB)__readgsqword(TEB_PPEB_OFFSET64);

    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY listHead = &ldr->InMemoryOrderModuleList;

    PLIST_ENTRY ldrListEntry = listHead->Flink;

    PBYTE kernel32Base = NULL;

    while (ldrListEntry != listHead) {
        PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(ldrListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                                //LDR_DATA_TABLE_ENTRY::BaseDllName isnt defined in winternl.h
        PUNICODE_STRING dllName = (PUNICODE_STRING)&ldrEntry->Reserved4;

        if (WStrCmp(dllName->Buffer, L"KERNEL32.DLL")) {
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

        if (StrCmp(exportName, "LoadLibraryA")) {
            loadLibraryA = (PVOID)(kernel32Base + exportAddrRVA[i]);
        }

        else if (StrCmp(exportName, "GetProcAddress")) {
            getProcAddress = (PVOID)(kernel32Base + exportAddrRVA[i]);
        }
    }
}

PVOID LocateFunction(LPCSTR module, LPCSTR function) {
    return getProcAddress( loadLibraryA(module), function );
}

BOOL StrCmp(LPSTR s1, LPSTR s2) {
    while (*s1 != 0 && *s2 != 0) {
        if (*s1++ != *s2++) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOL WStrCmp(LPWSTR s1, LPWSTR s2) {
    while (*s1 != 0 && *s2 != 0) {
        if (*s1++ != *s2++) {
            return FALSE;
        }
    }
    return TRUE;
}
