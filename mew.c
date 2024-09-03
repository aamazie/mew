#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Example malware signatures (these are simplified for demonstration)
const char *malware_signatures[] = {
    "\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2", // Example shellcode signature
    "\xeb\xfe",                                     // Infinite loop, common in shellcode
    "\x90\x90\x90\x90",                             // NOP sled, often used in exploits
    "\xcc\xcc\xcc\xcc",                             // INT3 instructions, potential breakpoint traps
    "\x6a\x02\x58\xcd\x80",                         // Syscall payload
};

#define SIGNATURE_COUNT (sizeof(malware_signatures) / sizeof(malware_signatures[0]))

// Function to read a file into memory
uint8_t* read_file_to_memory(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *buffer = (uint8_t *)malloc(*size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, *size, file);
    fclose(file);
    return buffer;
}

// Function to scan memory for malware signatures
int scan_for_malware(const uint8_t *memory, size_t memory_size) {
    for (size_t i = 0; i < memory_size; ++i) {
        for (size_t j = 0; j < SIGNATURE_COUNT; ++j) {
            size_t signature_length = strlen(malware_signatures[j]);
            if (i + signature_length <= memory_size &&
                memcmp(memory + i, malware_signatures[j], signature_length) == 0) {
                printf("Malware detected: Signature %zu found at memory address %p\n", j, (void *)(memory + i));
                return 1;  // Malware found
            }
        }
    }
    return 0;  // No malware found
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    size_t memory_size;
    uint8_t *memory = read_file_to_memory(argv[1], &memory_size);
    if (!memory) {
        return 1;
    }

    if (scan_for_malware(memory, memory_size)) {
        printf("Malware detected in file!\n");
    } else {
        printf("No malware detected in file.\n");
    }

    free(memory);
    return 0;
}
