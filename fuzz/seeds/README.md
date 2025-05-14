# Fuzz Seed Corpus

This directory contains deterministic seed inputs used to prime fuzz
coverage for Amulet-Core.  Each file is a raw, **binary** blob whose file
name encodes the seed identifier from `fuzz_plan.md` (e.g. `S1.bin`).

The actual hex listed in the plan should be written to these files using:

```bash
xxd -r -p <<< "<hex>" > fuzz/seeds/S1.bin
```

These seeds are **NOT** text files; keep them committed as binary to avoid
newline corruption on Windows/macOS. 