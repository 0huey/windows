#include "main.h"

__declspec( dllexport ) VOID DllRegisterServer(VOID) {
    FindKernel32();

    PGET_CURRENT_PROCESS_ID GetCurrentProcessId = LocateFunction("kernel32.dll", "GetCurrentProcessId");
    PGET_CURRENT_PROCESS    GetCurrentProcess   = LocateFunction("kernel32.dll", "GetCurrentProcess");
    PGET_MODULE_BASE_NAME_A GetModuleBaseNameA  = LocateFunction("psapi.dll", "GetModuleBaseNameA");
    PMESSAGE_BOX_A          MessageBoxA         = LocateFunction("user32.dll", "MessageBoxA");
    PS_PRINTF_S             sprintf_s           = LocateFunction("msvcrt.dll", "sprintf_s");

    HANDLE hProcess = GetCurrentProcess();

    CHAR procName[PROC_NAME_LEN];

    GetModuleBaseNameA(hProcess, NULL, procName, PROC_NAME_LEN);

    CHAR msg[MSG_LEN];
    
    sprintf_s(msg, MSG_LEN, "Running from %s PID %ld", procName, GetCurrentProcessId());

    MessageBoxA(0, msg, "Injected", MB_OK);
}
