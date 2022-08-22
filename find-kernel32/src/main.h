#include <windows.h>
#include "find-kernel32.h"

typedef int MESSAGE_BOX_A(HWND, LPCSTR, LPCSTR, UINT);

typedef MESSAGE_BOX_A *PMESSAGE_BOX_A;

PMESSAGE_BOX_A fMessageBoxA = NULL;
