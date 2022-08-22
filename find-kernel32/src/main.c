#include "main.h"

__declspec( dllexport ) VOID DllRegisterServer(VOID) {
    FindKernel32();

    fMessageBoxA = LocateFunction("user32.dll", "MessageBoxA");
    
    fMessageBoxA(0, "test", "test", MB_OK);
}
