#include <windows.h>
#include <winternl.h>

#define TEB_PPEB_OFFSET64 0x60

#define HASH_KERNEL32 0xc90d510cad54a0a2    // KERNEL32.DLL
#define HASH_LOAD_LIB 0xcaa7fee29f38fc48    // LoadLibraryA
#define HASH_GET_PROC 0x4ee7f7c0d11acdac    // GetProcAddress

VOID FindKernel32(VOID);
PVOID LocateFunction(LPCSTR, LPCSTR);
DWORD64 HashString(PVOID, INT);

typedef HMODULE LOAD_LIBRARY_A(LPCSTR);
typedef PVOID GET_PROC_ADDRESS(HMODULE, LPCSTR);

typedef LOAD_LIBRARY_A *PLOAD_LIBRARY_A;
typedef GET_PROC_ADDRESS *PGET_PROC_ADDRESS;
