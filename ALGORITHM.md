# ADPCM Codec DLL — Algorithm Analysis

## Overview

This document describes the audio compression algorithms implemented in
the reverse-engineered ADPCM DLL. The DLL is a multi-codec library
supporting 14 internal encoding methods across four families: a custom
successive-approximation ADPCM ("ADPCM2"), a simpler variant ("ADPCM1"),
a segmented non-linear PCM compander, and passthrough modes for linear
PCM. An additional G.726 codec is present in the method tables but not
wired into the encode/decode paths.

The DLL was most likely developed by a Japanese team, evidenced by the
string "Non-liner PCM" (a common L/R substitution in Japanese English).

## Codec Methods

The DLL defines 14 internal method codes (0–13), of which 10 are exposed
through the public API via an indirection table.

### ADPCM2 Family (Custom Successive-Approximation ADPCM)

ADPCM2 is the primary codec. It is available at six bit depths, each
encoding one sample into a single byte containing a sign bit followed by
magnitude bits:

| Method   | Code | Bits | Sign Mask | Magnitude Bits | Max Step Index |
|----------|------|------|-----------|----------------|----------------|
| 2-bit    |  13  |   2  |  `0x02`   |       1        |       90       |
| 4-bit    |   0  |   4  |  `0x08`   |       3        |       90       |
| 5-bit    |   1  |   5  |  `0x10`   |       4        |       81       |
| 6-bit    |   2  |   6  |  `0x20`   |       5        |       71       |
| 7-bit    |   3  |   7  |  `0x40`   |       6        |       63       |
| 8-bit    |   4  |   8  |  `0x80`   |       7        |       63       |

All ADPCM2 variants operate on 16-bit signed PCM samples internally, with
no prescaling.

### ADPCM1 (Simpler Variant)

| Method   | Code | Bits | Sign Mask | Magnitude Bits | Max Step Index |
|----------|------|------|-----------|----------------|----------------|
| 4-bit    |   5  |   4  |  `0x08`   |       3        |       48       |

ADPCM1 uses the same encoding format as 4-bit ADPCM2 but operates at
12-bit internal precision: samples are right-shifted by 4 before encoding
and left-shifted by 4 after decoding. It also has a smaller step size
table (49 entries vs. 91) and a gentler step index adaptation curve.

### Non-Linear PCM

| Method        | Code | Bits |
|---------------|------|------|
| Non-liner PCM |   7  |   8  |

A segmented piecewise-linear companding scheme that compresses 16-bit
samples into 8 bits. It operates at 10-bit internal precision (samples
prescaled by >>6, postscaled by <<6). See the dedicated section below.

### Passthrough Modes

| Method    | Code | Notes                    |
|-----------|------|--------------------------|
| 8-bit PCM |   6  | Unsigned-to-signed conversion |
| 16-bit PCM|   8  | Direct copy                   |

### G.726 (Present but Inactive)

Codes 9–12 correspond to G.726 at 2/3/4/5 bits. The per-method tables
contain entries for these codes, but the encode and decode dispatch paths
treat them as no-ops. The adpcmReturnBytes function passes counts through
unchanged for these methods. They are not exposed via the public API.

---

## Codec Context Structure

The DLL uses a singleton context object at a fixed address. It contains
format parameters and separate encoder/decoder channel state banks:

```
Offset  Size   Field
──────  ────   ─────────────────────────
+0x00   4      (reserved/padding)
+0x04   1      methodCode         Internal method code (0–13)
+0x05   1      (padding)
+0x06   2      bitsPerSample      PCM format: 8 or 16
+0x08   2      numChannels        Channel count (typically 1 or 2)
+0x0A   2      (padding)
+0x0C   12     encChannels[0]     Encoder state, channel 0
+0x18   12     encChannels[1]     Encoder state, channel 1
+0x24   12     decChannels[0]     Decoder state, channel 0
+0x30   12     decChannels[1]     Decoder state, channel 1
```

Each channel state block is 12 bytes:

```
Offset  Size   Field
──────  ────   ─────────────────────────
+0x00   4      predicted          Current/predicted sample value
+0x04   2      stepIndex          Index into the step size table
+0x06   1      encodedByte        Encoded output (encoder) or input (decoder)
+0x07   1      (padding)
+0x08   4      accumulator        Running reconstructed sample value
```

The encoder accesses channels at `context + (ch + 1) × 12`, while the
decoder uses `context + (ch + 3) × 12`. For stereo, there is no overlap
between encoder and decoder states.

---

## ADPCM2 Encoding Algorithm

ADPCM2 uses successive approximation to encode the difference between the
current sample and the previously reconstructed sample. The algorithm is
conceptually similar to IMA-ADPCM but differs in key details: the step
size table geometry, the adaptation curve, and the variable bit depth.

### Encoding One Sample

Given the current PCM sample and the channel state:

**1. Prescale (ADPCM1 only)**

For ADPCM1, the sample is right-shifted by 4 to reduce it to 12-bit
range. ADPCM2 operates at full 16-bit precision.

**2. Compute the prediction error**

```
diff = sample − accumulator
```

Where `accumulator` holds the reconstructed value from the previous
sample. This difference is clamped to the method's precision range
(±32767 for ADPCM2, ±2047 for ADPCM1).

**3. Encode the sign bit**

The sign of the difference is stored as the MSB of the encoded byte:

```
if (sample < accumulator):
    encodedByte = 1        // sign bit set = negative direction
    direction = −1
else:
    encodedByte = 0
    direction = +1
```

**4. Look up the step size**

The step size is read from a 2D table indexed by the current step index
and method code:

```
stepSize = stepSizeTable[stepIndex × 16 + methodCode]
```

The table has 91 rows. Each row contains step sizes for all 16 method
slots (only ADPCM columns are non-zero). The step sizes grow
exponentially at approximately 1.08× per row, doubling roughly every 9
steps. Column relationships follow the number of magnitude bits:

- 4-bit methods (cols 0, 5, 13): base step size
- 5-bit (col 1): 2× base
- 6-bit (col 2): 4× base
- 7-bit, 8-bit (cols 3, 4): 8× base (identical)

**5. Successive approximation loop**

For each magnitude bit from MSB to LSB (total of `bits − 1` iterations):

```
encodedByte <<= 1              // shift to make room for next bit

if (direction == +1 and |diff| >= stepSize) or
   (direction == −1 and |diff| >  stepSize):
    encodedByte |= 1           // set this magnitude bit
    accumulator += direction × stepSize
    |diff| -= stepSize

stepSize >>= 1                 // halve step size for next bit
```

This binary search progressively refines the reconstruction. At each
level, the algorithm decides whether the remaining error is large enough
to warrant the current quantum. The asymmetric comparison (≥ vs >) for
positive and negative directions avoids double-counting at boundaries.

**6. Half-step correction**

After the loop, the remaining (halved) step size is applied
unconditionally:

```
accumulator += direction × stepSize
```

This centres the reconstruction between quantisation levels, reducing the
expected error by half a quantum. This is a standard ADPCM technique.

**7. Clamp the accumulator**

The accumulator is clamped to the valid sample range for the method.

**8. Update the step index**

The magnitude portion of the encoded byte (sign bit stripped) is used to
look up a step index adjustment from a second 2D table:

```
magnitude = encodedByte & ~signMask
adjustment = stepAdjustTable[magnitude × 16 + methodCode]
stepIndex = clamp(stepIndex + adjustment, 0, maxStepIndex)
```

Small magnitudes produce negative adjustments (decreasing the step size
for quiet, well-predicted signals), while large magnitudes produce
positive adjustments (increasing the step size for loud transients or
rapid changes).

**9. Postscale (ADPCM1 only)**

For ADPCM1, the reconstructed sample is left-shifted by 4 to return to
16-bit range.

### Decoding One Sample

Decoding is the inverse operation. Given an encoded byte:

1. Read the step size from the table using the current step index.
2. Extract the sign bit to determine the direction.
3. For each magnitude bit (MSB to LSB), shift the encoded byte right by
   the bit position, extract the low bit, and if set, add
   `direction × stepSize` to the accumulator. Halve the step size after
   each bit.
4. Apply the half-step correction.
5. Update the step index using the magnitude lookup table.
6. Clamp the accumulator and set the predicted (output) sample.

### Step Index Adaptation

The adaptation strategy varies by bit depth:

| Method     | Magnitude range | Adjustment range | Character          |
|------------|-----------------|------------------|--------------------|
| 2-bit ADPCM2 | 0–1          | −2 to +3         | Very aggressive    |
| 4-bit ADPCM2 | 0–7          | −2 to +11        | Aggressive         |
| 4-bit ADPCM1 | 0–7          | −1 to +8         | Moderate           |
| 5-bit ADPCM2 | 0–15         | −2 to +15        | Moderate           |
| 6-bit ADPCM2 | 0–31         | −2 to +28        | Gradual            |
| 7-bit ADPCM2 | 0–63         | −2 to +25        | Gradual            |
| 8-bit ADPCM2 | 0–127        | always −1        | Constant decay     |

The 8-bit mode is notable: it always decreases the step index by 1,
regardless of the magnitude. With 7 magnitude bits providing fine
quantisation, there is little need for aggressive adaptation — the codec
relies on raw precision rather than step tracking.

---

## Non-Linear PCM Companding

The Non-linear PCM codec (method 7) compresses 16-bit samples to 8 bits
using a segmented piecewise-linear transfer curve, conceptually similar
to ITU-T µ-law or A-law but with a simpler 3-segment-per-polarity
design.

### Transfer Curve

The curve is symmetric around zero, with three segments of increasing
step size per polarity:

```
Sample range          Encoded range    Step    Segment
─────────────────     ─────────────    ────    ────────
     0 to  +4032       0 to   63        64    Fine (near zero)
 +4096 to +16128      64 to  111       256    Medium
+16384 to +31744     112 to  127      1024    Coarse

−32768 to −17408     128 to  143      1024    Coarse
−16384 to  −4352     144 to  191       256    Medium
 −4096 to    −64     192 to  255        64    Fine (near zero)
```

The step sizes correspond to the prescaler's >>6 shift: the base quantum
is 64 (the smallest resolvable difference after >>6 and <<6). The medium
segment (>>2 relative to base) has step 64 × 4 = 256, and the coarse
segment (>>4) has step 64 × 16 = 1024.

### Encoding

The encoder classifies the prescaled sample (after >>6) into one of 16
amplitude segments via `(sample >> 6) + 8`, then maps that to one of 5
groups:

| Group | Segments | Shift | Byte formula             |
|-------|----------|-------|--------------------------|
|   0   | 0–3      |  >>4  | `~(lowByte + 0x60)` (NOT of biased) |
|   1   | 4–6      |  >>2  | `~(~lowByte + 0x30)` = `lowByte − 0x30`  |
|   2   | 7–8      | none  | `lowByte` directly       |
|   3   | 9–11     |  >>2  | `lowByte + 0x30`         |
|   4   | 12–15    |  >>4  | `lowByte + 0x60`         |

The encoding is symmetric: positive and negative samples of the same
amplitude produce bytes that are bitwise complements of each other
(via the NOT operations in groups 0 and 1).

After encoding, the sample is "reconstructed" by reversing the shift
(with quantisation loss) to maintain prediction state.

### Decoding

Decoding uses a 256-entry lookup table that maps each encoded byte
directly to a signed 16-bit sample value. This is faster than reversing
the segmented encoding arithmetic.

---

## Precision Pipeline

Each codec family applies prescaling and postscaling to match its
internal working precision:

```
              Prescale    Internal range        Postscale
              ────────    ──────────────        ─────────
ADPCM2:       (none)     −32768 to +32767       (none)
ADPCM1:         >>4      −2048  to +2047          <<4
Non-linear:     >>6      (segmented)              <<6
8-bit PCM:      >>8      −128   to +127           <<8
```

For 8-bit PCM input, the encoder additionally converts between unsigned
(0–255) and signed (−128 to +127) representations using XOR 0x80. The
internal representation always uses signed values, with 8-bit samples
shifted left by 8 to occupy the upper byte of a 16-bit word.

---

## Data Tables

All codec tables reside in a contiguous 10,496-byte region of read-only
data:

| Address     | Size    | Table                    |
|-------------|---------|--------------------------|
| `1003b000`  | 5,824 B | Step size (91 × 16 int32)|
| `1003c6c0`  | 4,096 B | Step adjust (128 × 16 int16)|
| `1003d6c0`  |    16 B | Method index map         |
| `1003d6d0`  |    16 B | Bits per method          |
| `1003d6e0`  |    16 B | Encoded byte mask        |
| `1003d6f0`  |    16 B | Sign mask                |
| `1003d700`  |   512 B | NL PCM decompand (256 int16)|

Both 2D tables use a stride of 16 columns (one per potential method
slot), with only the active ADPCM columns populated. This wastes some
space but allows a single indexed lookup without per-method table
pointer indirection.

### Step Size Table Geometry

The step sizes grow approximately exponentially at ~1.08× per row. At
row 0, the base step size for 4-bit ADPCM2 is 16. At row 90, it is
16,302. Each additional bit of magnitude resolution doubles the step
size in the same row: a 5-bit method sees 2× the base, 6-bit sees 4×,
and so on. This scaling ensures that each method's step sizes cover the
full 16-bit sample range at the top of their respective index ranges.

---

## Public API

The DLL exports 7 functions. All use a singleton context object which is
passed via ECX (thiscall convention) after the exported cdecl wrappers
load it from a fixed address.

| Export              | Purpose                                        |
|---------------------|------------------------------------------------|
| `adpcmGetNumMethod` | Returns 10 (number of exposed methods)         |
| `adpcmGetMethod`    | Copies method name string to caller's buffer   |
| `adpcmReset`        | Initialises context: method, format, zeroes state |
| `adpcmEva`          | Trial encode+reconstruct for quality evaluation |
| `adpcmEnc`          | Encode PCM → compressed                        |
| `adpcmDec`          | Decode compressed → PCM                        |
| `adpcmReturnBytes`  | Compute output byte count for a given direction|

The `adpcmEva` function is notable: it encodes each sample in-place, then
writes the reconstructed (decoded) sample back to the input buffer. The
caller can then compare original and reconstructed buffers to measure
distortion for a given method, enabling quality-driven method selection.
