CC = x86_64-w64-mingw32-gcc.exe
CC32 = i686-w64-mingw32-gcc.exe
CFLAGS = -Wall
SRC = $(wildcard src/*.c)

dll:
	$(CC) $(CFLAGS) -shared -o find-kernel32.dll $(SRC)

strip:
	strip.exe --strip-unneeded -o find-kernel32.dll find-kernel32.dll 2> /dev/null || true
