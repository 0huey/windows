#include "main.h"

PGET_CURRENT_PROCESS_ID getCurrentProcessId = NULL;
PGET_CURRENT_PROCESS    getCurrentProcess   = NULL;
PGET_MODULE_BASE_NAME_A getModuleBaseNameA  = NULL;
PMESSAGE_BOX_A          messageBoxA         = NULL;
PS_PRINTF_S             s_printf_s          = NULL;


__declspec( dllexport ) VOID DllRegisterServer(VOID) {
    FindKernel32();

    getCurrentProcessId = LocateFunction("kernel32.dll", "GetCurrentProcessId");
    getCurrentProcess   = LocateFunction("kernel32.dll", "GetCurrentProcess");
    getModuleBaseNameA  = LocateFunction("psapi.dll", "GetModuleBaseNameA");
    messageBoxA         = LocateFunction("user32.dll", "MessageBoxA");
    s_printf_s          = LocateFunction("msvcrt.dll", "sprintf_s");

    HANDLE hProcess = getCurrentProcess();

    CHAR procName[PROC_NAME_LEN];

    getModuleBaseNameA(hProcess, NULL, procName, PROC_NAME_LEN);

    CHAR msg[MSG_LEN];

    s_printf_s(msg, MSG_LEN, "Running from %s PID %ld", procName, getCurrentProcessId());

    messageBoxA(0, msg, "Injected", MB_OK);
}
