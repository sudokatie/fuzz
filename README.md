# fuzz

Coverage-guided fuzzer for finding bugs in software. Because sometimes the best way to find bugs is to throw garbage at your code until something breaks.

## Why This Exists?

AFL and libFuzzer are fantastic, but sometimes you want something simpler to understand, hack on, or learn from. This is that thing. A fuzzer you can actually read the source of without needing a PhD.

## Features

- Coverage-guided mutation (find new paths, keep interesting inputs)
- Multiple mutation strategies (bit flips, arithmetic, block operations, havoc)
- Crash deduplication (same bug, one report)
- Input minimization (smallest reproducer)
- Parallel fuzzing (more cores, more bugs)
- Terminal UI (watch the chaos unfold)

## Quick Start

```bash
# Build a target with coverage instrumentation
clang -fsanitize-coverage=trace-pc-guard -o target target.c

# Start fuzzing
fuzz run ./target -i seeds/ -o output/

# Minimize a crash
fuzz minimize crash_input ./target

# Triage crashes
fuzz triage output/crashes/ ./target
```

## Commands

```
fuzz run <target>       Start fuzzing
fuzz minimize <input>   Minimize crashing input
fuzz triage <dir>       Classify and deduplicate crashes
fuzz cov <corpus>       Show corpus coverage
fuzz corpus-min         Minimize corpus to essential inputs
```

## Options

```
-i, --input <dir>      Seed corpus directory
-o, --output <dir>     Output directory (default: fuzz_output)
-t, --timeout <ms>     Execution timeout (default: 1000)
-m, --memory <mb>      Memory limit
-j, --jobs <n>         Parallel fuzzing jobs (default: 1)
-x, --dict <file>      Dictionary for mutations
--no-ui                Disable terminal UI
```

## How It Works

1. Load seed inputs (or generate random ones)
2. Pick an input, mutate it
3. Run the target with mutated input
4. If it crashes: save it, deduplicate
5. If it finds new code paths: add to corpus
6. Repeat until heat death of universe (or Ctrl+C)

## Philosophy

1. Simple beats clever
2. Fast beats featured
3. Readable beats optimized (mostly)
4. Find bugs, not false positives

## License

MIT

---

*Throw enough garbage at code and eventually it confesses its secrets.*
