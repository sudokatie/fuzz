// Null pointer dereference target for fuzzing tests.
// Triggers crash on specific input pattern "ABC".
// Compile: clang -o null_deref null_deref.c

#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[8];

    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n < 3) {
        return 0;
    }

    // Crash on magic sequence
    if (buf[0] == 'A' && buf[1] == 'B' && buf[2] == 'C') {
        int *p = (int *)0;
        *p = 42;  // Null pointer dereference
    }

    return 0;
}
