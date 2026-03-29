// Deep path exploration target for fuzzing tests.
// Requires specific byte sequence to trigger crash.
// Tests coverage-guided fuzzing effectiveness.
// Compile: clang -o deep_crash deep_crash.c

#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[8];

    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 6) {
        return 0;
    }

    // Multi-stage check - requires coverage guidance to solve
    if (buf[0] == 'F') {
        if (buf[1] == 'U') {
            if (buf[2] == 'Z') {
                if (buf[3] == 'Z') {
                    if (buf[4] == 'M') {
                        if (buf[5] == 'E') {
                            // Crash!
                            int *p = (int *)0;
                            *p = 1;
                        }
                    }
                }
            }
        }
    }

    return 0;
}
