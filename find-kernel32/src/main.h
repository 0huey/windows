#include <windows.h>
#include "find-kernel32.h"

#define MSG_LEN 256
#define PROC_NAME_LEN 128

typedef DWORD GET_CURRENT_PROCESS_ID();
typedef GET_CURRENT_PROCESS_ID *PGET_CURRENT_PROCESS_ID;

typedef HANDLE GET_CURRENT_PROCESS();
typedef GET_CURRENT_PROCESS *PGET_CURRENT_PROCESS;

typedef DWORD GET_MODULE_BASE_NAME_A(HANDLE, HMODULE, LPSTR, DWORD);
typedef GET_MODULE_BASE_NAME_A *PGET_MODULE_BASE_NAME_A;

typedef int MESSAGE_BOX_A(HWND, LPCSTR, LPCSTR, UINT);
typedef MESSAGE_BOX_A *PMESSAGE_BOX_A;

typedef int S_PRINTF_S(char *, size_t, const char *, ...);
typedef S_PRINTF_S *PS_PRINTF_S;
