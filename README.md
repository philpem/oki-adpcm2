# ADPCM DLL Reverse Engineering

A complete reverse engineering of a proprietary Windows DLL implementing
multi-method ADPCM audio compression and decompression, reconstructed
from x86 assembly (Ghidra disassembly) into clean, documented C.

## What's in the DLL

The DLL implements 14 audio encoding methods across four families:

| Family           | Methods                          | Compression ratio |
|------------------|----------------------------------|-------------------|
| **ADPCM2**       | 2, 4, 5, 6, 7, 8-bit variants   | 8:1 down to 2:1  |
| **ADPCM1**       | 4-bit only                       | 4:1               |
| **Non-linear PCM** | 8-bit segmented companding     | 2:1               |
| **Linear PCM**   | 8-bit and 16-bit passthrough     | 2:1 or 1:1        |

G.726 entries exist in the tables but are not wired into the
encode/decode paths.

## Repository Structure

```
├── standalone/               Clean, compilable reimplementation
│   ├── adpcm_codec.h           Public API header
│   └── adpcm_codec.c           Complete single-file implementation
│
├── src/                      Per-function reverse engineering notes
│   ├── adpcm.h                 Reconstructed structures
│   ├── entry.c                 DLL entry point (_DllMainCRTStartup)
│   ├── exports.c               Export table and thunk documentation
│   ├── methods.c               Method enumeration (GetNumMethod, GetMethod)
│   ├── reset.c                 Context initialisation (adpcmReset)
│   ├── evaluate.c              Quality evaluation (adpcmEva)
│   ├── encode.c                Encoder outer loop (adpcmEnc)
│   ├── decode.c                Decoder outer loop (adpcmDec)
│   ├── encode_sample.c         Core ADPCM encode algorithm
│   ├── decode_sample.c         Core ADPCM decode algorithm
│   ├── return_bytes.c          Byte count calculator (adpcmReturnBytes)
│   ├── tables_and_helpers.c    Per-method tables + clamp/scale helpers
│   ├── nlpcm_table.c           Non-linear PCM decompanding table
│   ├── step_size_table.c       Step size table (91×16 int32)
│   └── step_adjust_table.c     Step index adjustment table (128×16 int16)
│
├── data/                     Raw hex dumps from Ghidra
│   ├── step_size_raw.hex
│   └── step_adjust_raw.hex
│
└── docs/
    ├── ALGORITHM.md            Detailed algorithm documentation
    └── TODO.md                 Tracking of completed/remaining work
```

## Using the Standalone Reimplementation

The `standalone/` directory contains a drop-in C reimplementation with
no dependencies beyond libc.

### Building

```bash
gcc -c standalone/adpcm_codec.c -o adpcm_codec.o
```

### API Usage

```c
#include "adpcm_codec.h"

AdpcmContext ctx;

/* List available methods */
for (int i = 0; i < adpcm_get_num_methods(); i++) {
    printf("%d: %s\n", i, adpcm_get_method_name(i));
}

/* Initialise for 4-bit ADPCM2, 16-bit stereo */
adpcm_reset(&ctx, 2, 16, 2);

/* Encode */
uint32_t out_size = adpcm_return_bytes(&ctx, ADPCM_DIRECTION_ENCODE, pcm_size);
uint32_t samples = adpcm_encode(&ctx, pcm_data, compressed, pcm_size);

/* Decode */
uint32_t pcm_out_size = adpcm_return_bytes(&ctx, ADPCM_DIRECTION_DECODE, sample_count);
adpcm_decode(&ctx, compressed, pcm_out, sample_count);

/* Quality evaluation: encode+reconstruct in-place */
adpcm_evaluate(&ctx, pcm_buffer, buffer_size);
/* pcm_buffer now contains reconstructed samples for comparison */
```

### Method Index Reference

| API Index | Name           | Internal Code | Compression |
|-----------|----------------|---------------|-------------|
| 0         | 4bit ADPCM1    | 5             | 4:1         |
| 1         | 2bit ADPCM2    | 13            | 8:1         |
| 2         | 4bit ADPCM2    | 0             | 4:1         |
| 3         | 5bit ADPCM2    | 1             | 3.2:1       |
| 4         | 6bit ADPCM2    | 2             | 2.7:1       |
| 5         | 7bit ADPCM2    | 3             | 2.3:1       |
| 6         | 8bit ADPCM2    | 4             | 2:1         |
| 7         | Non-liner PCM  | 7             | 2:1         |
| 8         | 8bit PCM       | 6             | 2:1         |
| 9         | 16bit PCM      | 8             | 1:1         |

## Algorithm Summary

The core ADPCM2 encoder uses **successive approximation** — similar in
concept to IMA-ADPCM but with a custom exponential step size table
(~1.08× growth per row) and per-method adaptation curves.

For each sample:

1. Compute the difference from the previous reconstructed sample
2. Encode the sign as the MSB
3. Binary-search the magnitude bits against a halving step size
4. Apply a half-step correction for minimal reconstruction error
5. Adapt the step size via a 2D lookup table

See [docs/ALGORITHM.md](docs/ALGORITHM.md) for the full description
including the non-linear PCM companding scheme, the precision pipeline,
table geometry, and step adaptation analysis.

## Original DLL Details

| Item              | Address       | Notes |
|-------------------|---------------|-------|
| Entry point       | `0x10005020`  | Standard MSVC `_DllMainCRTStartup` |
| Singleton context | `0x1004dc88`  | Loaded into ECX for thiscall dispatch |
| Step size table   | `0x1003b000`  | 91 × 16 int32 (5,824 bytes) |
| Adjust table      | `0x1003c6c0`  | 128 × 16 int16 (4,096 bytes) |
| Per-method tables | `0x1003d6c0`  | 4 × 16 bytes |
| NL PCM table      | `0x1003d700`  | 256 int16 (512 bytes) |

All exported functions are thunk trampolines (`JMP`) to wrappers that
load ECX with the context address before tail-calling the real
`__thiscall` implementations.
