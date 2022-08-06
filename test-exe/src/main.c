#include <windows.h>

int WINAPI WinMain(
        HINSTANCE hInstance,
        HINSTANCE hPrevInstance,
        LPSTR pCmdLine,
        int nCmdShow)
{
    MessageBox(NULL, "test", "hello, world!", MB_OK);
    return 0;
}