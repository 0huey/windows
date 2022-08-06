#include "main.h"

int main(int argc, char *argv[]) {
    BYTE                    *pRawPE;
    BYTE                    *pVirtualPE;
    IMAGE_DOS_HEADER        *pDOSHeader;
    IMAGE_FILE_HEADER       *pPEHeader;
    IMAGE_OPTIONAL_HEADER32 *pOptionalHeader32;
    IMAGE_OPTIONAL_HEADER64 *pOptionalHeader64;
    IMAGE_SECTION_HEADER    *pSectionHead;
    BOOL bits32;

    if (argc < 3) {
        printf("usage: %s INPUT OUTPUT\n", argv[0]);
        return 1;
    }

    pRawPE = LoadPE(argv[1]);

    if (!pRawPE) {
        return 1;
    }

    pDOSHeader = (IMAGE_DOS_HEADER *)pRawPE;

    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Bad DOS magic bytes: 0x%x\n", pDOSHeader->e_magic);
        return 1;
    }

    pPEHeader = (IMAGE_FILE_HEADER *)(pRawPE + pDOSHeader->e_lfanew + SIZE_OF_NT_SIGNATURE);

    if (pPEHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        pOptionalHeader32 = (IMAGE_OPTIONAL_HEADER32 *)((BYTE *)pPEHeader + sizeof(IMAGE_FILE_HEADER));
        bits32 = TRUE;
    }

    else if (pPEHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        pOptionalHeader64 = (IMAGE_OPTIONAL_HEADER64 *)((BYTE *)pPEHeader + sizeof(IMAGE_FILE_HEADER));
        bits32 = FALSE;
    }

    else {
        printf("Unsupported architecture: 0x%x\n", pPEHeader->Machine);
        return 1;
    }

    pVirtualPE = VirtualAlloc(NULL,
                            bits32 ? pOptionalHeader32->SizeOfImage : pOptionalHeader64->SizeOfImage,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);

    memcpy(pVirtualPE, pRawPE, bits32 ? pOptionalHeader32->SizeOfHeaders : pOptionalHeader64->SizeOfHeaders);

    pSectionHead = (IMAGE_SECTION_HEADER *)(bits32 ? (BYTE *)pOptionalHeader32 + sizeof(IMAGE_OPTIONAL_HEADER32) :
                                                     (BYTE *)pOptionalHeader64 + sizeof(IMAGE_OPTIONAL_HEADER64));

    //get first section header in new PE so we can edit it
    pSectionHead = (IMAGE_SECTION_HEADER *)((BYTE *)pSectionHead - pRawPE + pVirtualPE);

    for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
        memcpy(pVirtualPE + pSectionHead->VirtualAddress,
                pRawPE + pSectionHead->PointerToRawData,
                pSectionHead->SizeOfRawData);

        pSectionHead->PointerToRawData = pSectionHead->VirtualAddress;

        pSectionHead++;
    }

    HANDLE hOutputFile = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hOutputFile == INVALID_HANDLE_VALUE) {
        printf("cannot open output file\n");
        return 1;
    }

    if (!WriteFile(hOutputFile, pVirtualPE, bits32 ? pOptionalHeader32->SizeOfImage : pOptionalHeader64->SizeOfImage, NULL, NULL)) {
        printf("write file error\n");
        return 1;
    }

    CloseHandle(hOutputFile);

    return 0;
}


void * LoadPE(LPSTR szPath) {
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