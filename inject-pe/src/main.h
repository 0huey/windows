#include <windows.h>
#include <stdio.h>
#include <string.h>

#define OPEN_PROCESS_ACCESS_FLAGS PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE

PVOID LoadPE(LPSTR);

typedef PVOID _entryPoint();
