// Infinite loop target for fuzzing timeout tests.
// Hangs forever on input starting with 'X'.
// Compile: clang -o timeout timeout.c

#include <unistd.h>

int main(void) {
    char buf[4];

    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 1) {
        return 0;
    }

    // Hang on magic byte
    if (buf[0] == 'X') {
        while (1) {
            // Infinite loop
        }
    }

    return 0;
}
