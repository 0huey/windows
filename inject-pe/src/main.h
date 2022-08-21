#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SIZE_OF_NT_SIGNATURE 4

PVOID LoadPE(LPSTR);

typedef PVOID _entryPoint(PVOID);