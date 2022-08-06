CC = x86_64-w64-mingw32-gcc.exe
CC32 = i686-w64-mingw32-gcc.exe
CFLAGS = -Wall
SRC = $(wildcard src/*.c)

all: exe exe32 strip

exe:
	$(CC) $(CFLAGS) -o test64.exe $(SRC)

exe32:
	$(CC32) $(CFLAGS) -o test32.exe $(SRC)

strip:
	strip.exe --strip-unneeded -o test64.exe test64.exe 2> /dev/null || true
	strip.exe --strip-unneeded -o test32.exe test32.exe 2> /dev/null || true
