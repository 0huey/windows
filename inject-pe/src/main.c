#include "main.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("usage: %s DLL_PATH FUNC_NAME [PID]\n", argv[0]);
        return 1;
    }

    PBYTE pRawPE = LoadPE(argv[1]);
    LPSTR entryPointName = argv[2];

    if (!pRawPE) {
        return 1;
    }

    HANDLE remoteProcess = NULL;
    if (argc >= 4) {
        DWORD pid = atoi(argv[3]);
        remoteProcess = OpenProcess(OPEN_PROCESS_ACCESS_FLAGS, FALSE, pid);

        if (remoteProcess == NULL) {
            DWORD error = GetLastError();

            if (error == ERROR_ACCESS_DENIED) {
                printf("Access denied when opening remote process\n");
            }
            else if (error == ERROR_INVALID_PARAMETER) {
                printf("Invalid remote process ID\n");
            }
            else {
                printf("Error 0x%x when opening process\n", error);
            }
            return 1;
        }

        PROCESS_MACHINE_INFORMATION processInfo;
        memset(&processInfo, 0, sizeof(PROCESS_MACHINE_INFORMATION));

        GetProcessInformation(remoteProcess, ProcessMachineTypeInfo, &processInfo, sizeof(PROCESS_MACHINE_INFORMATION));

        if (processInfo.ProcessMachine != IMAGE_FILE_MACHINE_AMD64) {
            printf("Remote process is not 64 bit\n");
            return 1;
        }

    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pRawPE;

    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Bad DOS magic bytes: 0x%x\n", pDOSHeader->e_magic);
        return 1;
    }

    PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)(pRawPE + pDOSHeader->e_lfanew);

    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;

    if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("Unsupported architecture: 0x%x\n", pFileHeader->Machine);
        return 1;
    }

    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;

    //================================================================================================
    //Relocate and expand section headers

    PBYTE pVirtualPE = VirtualAlloc(NULL,
                                    pOptionalHeader64->SizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);

    memcpy(pVirtualPE, pRawPE, pOptionalHeader64->SizeOfHeaders);

    //================================================================================================
    //Relocate and expand section bodies

    PIMAGE_SECTION_HEADER pSectionHead = (PIMAGE_SECTION_HEADER)( (PBYTE)pOptionalHeader64 + sizeof(IMAGE_OPTIONAL_HEADER64) - pRawPE + pVirtualPE);

    for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++) {
        memcpy(pVirtualPE + pSectionHead->VirtualAddress,
                pRawPE + pSectionHead->PointerToRawData,
                pSectionHead->SizeOfRawData);

        //set these pointers equal so the bin can be dumped
        pSectionHead->PointerToRawData = pSectionHead->VirtualAddress;

        // or you could zero them
        /*
        pSectionHead->VirtualAddress = 0;
        pSectionHead->PointerToRawData = 0;
        pSectionHead->SizeOfRawData = 0;
        */

        pSectionHead++;
    }

    //================================================================================================
    //Do base relocations

    PVOID newBaseAddress;

    if (remoteProcess != NULL) {
        newBaseAddress = VirtualAllocEx(remoteProcess,
                                        NULL,
                                        pOptionalHeader64->SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    }
    else {
        //load in this process instead
        newBaseAddress = pVirtualPE;
    }

    PIMAGE_DATA_DIRECTORY pRelocDataDir = &pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    //first of some number of relocation blocks
    //https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up

    PIMAGE_BASE_RELOCATION pRelocTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pVirtualPE + pRelocDataDir->VirtualAddress);

    PIMAGE_BASE_RELOCATION pRelocEnd = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocTable + pRelocDataDir->Size);

    while (pRelocTable < pRelocEnd) {
        // each block begins with a header struct containing VirtualAddress and SizeOfBlock
        // following the header is an array of WORDs, the length of which can be calculated given the size of the block
        DWORD numMembers = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        PWORD members = (PWORD)((PBYTE)pRelocTable + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < numMembers; i++) {
            if (members[i] == 0) {
                //padding at end of block
                break;
            }

            /* each member is a 16 bit field
               the low 12 bits are an offset relative to VirtualAddress in the block header pRelocTable
               first translate this RVA to a pointer */
            PDWORD64 pRelocAddr = (PDWORD64)(pVirtualPE + pRelocTable->VirtualAddress + (members[i] & 0x0fff));

            //then rebase the address at this pointer
            *pRelocAddr = *pRelocAddr - pOptionalHeader64->ImageBase + (DWORD64)newBaseAddress;
        }

        //get pointer to next block at the end of this one
        pRelocTable = (PIMAGE_BASE_RELOCATION)((PBYTE)pRelocTable + pRelocTable->SizeOfBlock);
    }

    if (remoteProcess != NULL && !WriteProcessMemory(remoteProcess,
                                                     newBaseAddress,
                                                     pVirtualPE,
                                                     pOptionalHeader64->SizeOfImage,
                                                     NULL)) {
        printf("WriteProcessMemory failed\n");
        return 1;
    }

    //================================================================================================
    //Read export table and call function named in commandline

    PIMAGE_DATA_DIRECTORY pExportDataDir = &pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pVirtualPE + pExportDataDir->VirtualAddress);

    PDWORD exportNamesRVA = (PDWORD)((PBYTE)pVirtualPE + pExportDir->AddressOfNames);
    PDWORD exportAddrRVA  = (PDWORD)((PBYTE)pVirtualPE + pExportDir->AddressOfFunctions);

    _entryPoint *entryPoint = NULL;

    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {

        LPSTR exportName = (LPSTR)((PBYTE)pVirtualPE + exportNamesRVA[i]);

        if (!strcmp(exportName, entryPointName)) {
            entryPoint = (PVOID)((PBYTE)newBaseAddress + exportAddrRVA[i]);
            break;
        }
    }

    if (remoteProcess != NULL) {
        CreateRemoteThread(remoteProcess,
                           NULL,
                           0,
                           (LPTHREAD_START_ROUTINE)entryPoint,
                           NULL,
                           0,
                           NULL);
    }
    else {
        entryPoint();
    }

    return 0;
}

PVOID LoadPE(LPSTR szPath) {
    HANDLE hOpenFile;
    DWORD dFileSize;
    void *pRawPE;

    hOpenFile = CreateFileA(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hOpenFile == INVALID_HANDLE_VALUE) {
        printf("File open error\n");
        return NULL;
    }

    dFileSize = GetFileSize(hOpenFile, NULL);

    if (!dFileSize) {
        printf("0 byte file\n");
        goto ERR_CLOSE;
    }

    pRawPE = VirtualAlloc(NULL, dFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRawPE) {
        printf("VirtualAlloc error\n");
        goto ERR_CLOSE;
    }

    if (!ReadFile(hOpenFile, pRawPE, dFileSize, NULL, NULL)) {
        printf("read file error\n");
        goto ERR_FREE;
    }

    CloseHandle(hOpenFile);
    return pRawPE;

ERR_FREE:
    VirtualFree(pRawPE, dFileSize, MEM_DECOMMIT);
ERR_CLOSE:
    CloseHandle(hOpenFile);
    return NULL;
}
