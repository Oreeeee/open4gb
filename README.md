# Open 4GB
Automatically applies the large address aware characteristic to a 32-bit PE to allow it to use 4GB of RAM rather than 2GB.

## Compiling:
Compiler: GCC (Linux), TDM-GCC (Windows)
`gcc -m32 -O2 -s -o open4gb.exe main.c`

## Usage
`open4gb.exe executable_to_patch.exe`
