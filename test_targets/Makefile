# Build test targets for fuzzing
# Usage: make all

CC = clang
CFLAGS = -Wall -Wextra
ASAN_FLAGS = -fsanitize=address -g
SANCOV_FLAGS = -fsanitize-coverage=trace-pc-guard

TARGETS = overflow null_deref timeout deep_crash

.PHONY: all clean asan sancov

all: $(TARGETS)

overflow: overflow.c
	$(CC) $(CFLAGS) -o $@ $<

null_deref: null_deref.c
	$(CC) $(CFLAGS) -o $@ $<

timeout: timeout.c
	$(CC) $(CFLAGS) -o $@ $<

deep_crash: deep_crash.c
	$(CC) $(CFLAGS) -o $@ $<

# Build with AddressSanitizer
asan: $(addsuffix _asan,$(TARGETS))

%_asan: %.c
	$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $@ $<

# Build with SanitizerCoverage
sancov: $(addsuffix _sancov,$(TARGETS))

%_sancov: %.c
	$(CC) $(CFLAGS) $(SANCOV_FLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *_asan *_sancov
