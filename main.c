#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

// Some constants borrowed from Microsoft and unofficial docs
#define MZ_FILE_HEADER 0x5A4D // https://wiki.osdev.org/PE
#define PE_FILE_HEADER 0x00004550 // https://wiki.osdev.org/PE
#define CHARACTERISTICS_FIELD_OFFSET 0x16 // https://www.sunshine2k.de/reversing/tuts/tut_pe.htm
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020 // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s executable_to_patch.exe\n", argv[0]);
        return -1;
    }

    char *executableName = argv[1];
    printf("Patching %s\n", executableName);

    // Open the file
    FILE *fp;
    char filePath[1024];

    #ifdef _WIN32
    // Windows needs to have the full file path
    GetFullPathName(executableName, 1024, filePath, NULL);
    #else
    strncpy(filePath, executableName, 1024);
    #endif

    fp = fopen(filePath, "rb+");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file\n");
        return -2;
    }

    // Check for MZ header presence
    uint16_t mzBuf;
    fread(&mzBuf, sizeof(uint16_t), 1, fp);
    if (mzBuf != MZ_FILE_HEADER) {
        fprintf(stderr, "%s is not a valid executable (missing MZ header)\n", executableName);
        return -3;
    }

    // Search for the PE header
    int peOffset = 0;
    uint32_t peBuf = 0;
    for (int i = 0; peOffset == 0; i++) {
        fseek(fp, i, SEEK_SET);
        fread(&peBuf, sizeof(uint32_t), 1, fp);
        if (peBuf == PE_FILE_HEADER) {
            peOffset = i;
            break;
        }
    }
    printf("Found PE executable at 0x%02x\n", peOffset);

    printf("Adding large address aware characteristic...\n");
    fseek(fp, peOffset + CHARACTERISTICS_FIELD_OFFSET, SEEK_SET);
    uint16_t currChrctr = 0;
    uint16_t newChrctr = 0;

    // Get current characteristics
    fread(&currChrctr, sizeof(uint16_t), 1, fp);
    printf("Current characteristics: 0x%02x\n", currChrctr);

    // Set the bit
    newChrctr = currChrctr | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    printf("New characteristics: 0x%02x\n", newChrctr);

    printf("Writing new characteristics\n");
    fseek(fp, peOffset + CHARACTERISTICS_FIELD_OFFSET, SEEK_SET); // Go back to the cursor position before fread
    if (fwrite(&newChrctr, sizeof(uint16_t), 1, fp) == sizeof(uint16_t)) {
        printf("Wrote %d of bytes successfuly\n", sizeof(uint16_t));
    } else {
        fprintf(stderr, "Failed to write new characteristics: %s\n", strerror(errno));
        return -4;
    }

    printf("New characteristics written!\n");
    fclose(fp);
    return 0;
}
