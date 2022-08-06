#include <windows.h>
#include <stdio.h>
#include <string.h>

#define SIZE_OF_NT_SIGNATURE 4

void * LoadPE(LPSTR);