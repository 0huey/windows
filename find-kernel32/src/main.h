#include <windows.h>
#include "find-kernel32.h"

typedef int _MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);

_MessageBoxA *fMessageBoxA = NULL;