#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#define SIGNATURE_COUNT 5
#define BUFFER_SIZE 1024
#define STACK_CANARY 0xDEADC0DE

const char *malware_signatures[SIGNATURE_COUNT] = {
    "\x60\x89\xe5\x31\xc0\x31\xdb\x31\xc9\x31\xd2", // Example shellcode signature
    "\xeb\xfe",                                     // Infinite loop, common in shellcode
    "\x90\x90\x90\x90",                              // NOP sled, often used in exploits
    "\xcc\xcc\xcc\xcc",                              // INT3 instructions, potential breakpoint traps
    "\x6a\x02\x58\xcd\x80",                          // Syscall payload
};

// Function to check for stack overflow by verifying the canary value
void check_stack_overflow(uint32_t *canary) {
    if (*canary != STACK_CANARY) {
        printf("Stack overflow detected! Halting execution...\n");
        exit(EXIT_FAILURE);
    }
}

// Function to scan memory for malware signatures
int scan_for_malware(int fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        for (int i = 0; i < bytes_read; ++i) {
            for (int j = 0; j < SIGNATURE_COUNT; ++j) {
                size_t sig_len = strlen(malware_signatures[j]);
                if (i + sig_len < bytes_read && memcmp(buffer + i, malware_signatures[j], sig_len) == 0) {
                    printf("Malware detected: Signature %d found\n", j);
                    return 1;
                }
            }
        }
    }
    return 0;
}

// Function to check if a string is numeric
int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit(*str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

int main() {
    DIR *proc = opendir("/proc");
    struct dirent *entry;

    if (!proc) {
        perror("opendir");
        return EXIT_FAILURE;
    }

    while ((entry = readdir(proc)) != NULL) {
        if (is_numeric(entry->d_name)) {
            char mem_path[256];
            snprintf(mem_path, sizeof(mem_path), "/proc/%s/mem", entry->d_name);

            int fd = open(mem_path, O_RDONLY);
            if (fd < 0) {
                // Unable to open memory file, likely due to permission restrictions
                continue;
            }

            if (scan_for_malware(fd)) {
                printf("Malware detected in process: %s\n", entry->d_name);
                close(fd);
                break;
            }

            close(fd);
        }
    }

    closedir(proc);
    return 0;
}
