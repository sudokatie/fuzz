// Simple stack buffer overflow target for fuzzing tests.
// Compile: clang -o overflow overflow.c
// Compile with ASAN: clang -fsanitize=address -o overflow_asan overflow.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[16];
    char input[256];

    ssize_t n = read(STDIN_FILENO, input, sizeof(input) - 1);
    if (n <= 0) {
        return 0;
    }
    input[n] = '\0';

    // Vulnerable: no bounds checking
    strcpy(buf, input);

    return 0;
}
