/*
 * adpcm_codec.c — Reconstructed ADPCM Codec
 *
 * Reverse-engineered from a Windows DLL (Ghidra disassembly).
 * Standalone C99, no dependencies beyond libc.
 *
 * Organisation:
 *   §1  Step size tables (per algorithm)
 *   §2  Step index adjustment tables (per algorithm)
 *   §3  Non-linear PCM tables
 *   §4  Method descriptors
 *   §5  Helpers (clamp, prescale, postscale)
 *   §6  ADPCM core encode / decode
 *   §7  Non-linear PCM encode / decode
 *   §8  Top-level encode / decode / evaluate (PCM format handling)
 *   §9  Public API
 */

#include "adpcm_codec.h"
#include <string.h>


/* ================================================================
 * §1  Step Size Tables
 *
 * One table per unique step-size curve. Indexed by step_index.
 * Values grow at approximately 1.08× per row (doubling every ~9 steps).
 *
 * Higher bit-depth methods use proportionally larger step sizes:
 *   4-bit base, 5-bit ≈ 2×, 6-bit ≈ 4×, 7-bit ≈ 8×.
 *
 * ADPCM1 has its own slightly different curve (gentler growth)
 * and covers only 49 entries (max step index 48).
 * ================================================================ */

static const int32_t STEP_SIZE_ADPCM2_4BIT[91] = {
       16,    17,    18,    20,    21,    23,    25,    27,
       29,    31,    34,    37,    40,    43,    46,    50,
       54,    59,    63,    69,    74,    80,    86,    93,
      101,   109,   118,   127,   138,   149,   161,   173,
      187,   202,   219,   236,   255,   275,   298,   321,
      347,   375,   405,   437,   472,   510,   551,   595,
      643,   694,   750,   810,   875,   945,  1020,  1102,
     1190,  1286,  1388,  1500,  1620,  1749,  1889,  2040,
     2204,  2380,  2570,  2776,  2998,  3238,  3497,  3777,
     4079,  4406,  4758,  5139,  5550,  5994,  6474,  6991,
     7551,  8155,  8807,  9512, 10273, 11095, 11982, 12941,
    13976, 15095, 16302,
};
/* Also used by 2-bit ADPCM2 (same curve, same range) */

static const int32_t STEP_SIZE_ADPCM2_5BIT[82] = {
       32,    34,    37,    40,    43,    47,    50,    54,
       59,    63,    69,    74,    80,    87,    93,   101,
      109,   118,   127,   138,   149,   161,   173,   187,
      202,   219,   236,   255,   276,   298,   322,   347,
      375,   405,   438,   473,   510,   551,   596,   643,
      695,   750,   810,   875,   945,  1021,  1103,  1191,
     1286,  1389,  1500,  1620,  1750,  1890,  2041,  2205,
     2381,  2572,  2777,  3000,  3240,  3499,  3779,  4081,
     4408,  4760,  5141,  5553,  5997,  6477,  6995,  7555,
     8159,  8812,  9517, 10278, 11100, 11988, 12948, 13983,
    15102, 16310,
};

static const int32_t STEP_SIZE_ADPCM2_6BIT[72] = {
       64,    69,    74,    80,    87,    94,   101,   109,
      118,   127,   138,   149,   161,   174,   187,   203,
      219,   236,   255,   276,   298,   322,   347,   375,
      405,   438,   473,   511,   552,   596,   644,   695,
      751,   811,   876,   946,  1021,  1103,  1192,  1287,
     1390,  1501,  1621,  1751,  1891,  2042,  2206,  2382,
     2573,  2779,  3001,  3241,  3501,  3781,  4083,  4410,
     4763,  5144,  5555,  6000,  6480,  6998,  7558,  8163,
     8816,  9521, 10283, 11106, 11994, 12954, 13990, 15110,
};

static const int32_t STEP_SIZE_ADPCM2_7BIT[64] = {
    /* Also used by 8-bit ADPCM2 (identical step sizes, different adaptation) */
      128,   138,   149,   161,   174,   188,   203,   219,
      236,   255,   276,   298,   322,   348,   375,   406,
      438,   473,   511,   552,   596,   644,   695,   751,
      811,   876,   946,  1022,  1104,  1192,  1288,  1391,
     1502,  1622,  1752,  1892,  2043,  2207,  2384,  2574,
     2780,  3003,  3243,  3502,  3783,  4085,  4412,  4765,
     5146,  5558,  6003,  6483,  7002,  7562,  8167,  8820,
     9526, 10288, 11111, 12000, 12960, 13997, 15117, 16327,
};

static const int32_t STEP_SIZE_ADPCM1[49] = {
    /* ADPCM1 has its own curve — slightly steeper than ADPCM2 4-bit */
       16,    17,    19,    21,    23,    25,    28,    31,
       34,    37,    41,    45,    50,    55,    60,    66,
       73,    80,    88,    97,   107,   118,   130,   143,
      157,   173,   190,   209,   230,   253,   279,   307,
      337,   371,   408,   449,   494,   544,   598,   658,
      724,   796,   876,   963,  1060,  1166,  1282,  1411,
     1552,
};


/* ================================================================
 * §2  Step Index Adjustment Tables
 *
 * One table per method, indexed by the magnitude portion of the
 * encoded byte (sign bit stripped).
 *
 * Small magnitudes (quiet, well-predicted signals) produce negative
 * adjustments → step size decreases for finer resolution.
 *
 * Large magnitudes (transients, prediction failures) produce positive
 * adjustments → step size increases to track the signal.
 * ================================================================ */

static const int16_t STEP_ADJUST_ADPCM2_2BIT[2] = {
    -2,   3,
};

static const int16_t STEP_ADJUST_ADPCM2_4BIT[8] = {
    -2,  -2,  -2,  -2,   2,   6,   9,  11,
};

static const int16_t STEP_ADJUST_ADPCM2_5BIT[16] = {
    -2,  -2,  -2,  -2,  -1,  -1,  -1,  -1,
     2,   5,   7,   9,  11,  12,  14,  15,
};

static const int16_t STEP_ADJUST_ADPCM2_6BIT[32] = {
    -2,  -2,  -2,  -2,  -2,  -2,  -2,  -2,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     1,   3,   5,   6,   9,  10,  12,  14,
    16,  18,  19,  21,  23,  25,  27,  28,
};

static const int16_t STEP_ADJUST_ADPCM2_7BIT[64] = {
    -2,  -2,  -2,  -2,  -2,  -2,  -2,  -2,
    -2,  -2,  -2,  -2,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     0,   1,   2,   3,   3,   4,   5,   6,
     6,   7,   8,   9,   9,  10,  11,  12,
    12,  13,  14,  15,  15,  16,  17,  18,
    18,  19,  20,  21,  21,  22,  23,  24,
};

static const int16_t STEP_ADJUST_ADPCM2_8BIT[128] = {
    /* 8-bit always returns −1 or −2 regardless of magnitude.
       The codec relies on raw precision, not aggressive adaptation. */
    -2,  -2,  -2,  -2,  -2,  -2,  -2,  -2,
    -2,  -2,  -2,  -2,  -2,  -2,  -2,  -2,
    -2,  -2,  -2,  -2,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,   0,  -1,  -1,  -1,  -1,  -1,  -1,  /* magnitude 65 is 0, not −1 */
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
};

static const int16_t STEP_ADJUST_ADPCM1[8] = {
    /* Gentler adaptation than ADPCM2 4-bit: floor is −1, not −2 */
    -1,  -1,  -1,  -1,   2,   4,   6,   8,
};


/* ================================================================
 * §3  Non-Linear PCM Tables
 *
 * A 3-segment piecewise-linear companding curve, symmetric about zero.
 * Compresses 16-bit samples into 8 bits (after >>6 prescaling).
 *
 * Segment layout:
 *   Near zero (±4032):  step 64,   64 entries per polarity
 *   Moderate (±16128):  step 256,  48 entries per polarity
 *   Large (±31744):     step 1024, 16 entries per polarity
 * ================================================================ */

/* Decompanding table: encoded byte (0–255) → signed 16-bit sample */
static const int16_t NLPCM_DECOMPRESS[256] = {
    /* Near zero positive (step 64) */
         0,    64,   128,   192,   256,   320,   384,   448,
       512,   576,   640,   704,   768,   832,   896,   960,
      1024,  1088,  1152,  1216,  1280,  1344,  1408,  1472,
      1536,  1600,  1664,  1728,  1792,  1856,  1920,  1984,
      2048,  2112,  2176,  2240,  2304,  2368,  2432,  2496,
      2560,  2624,  2688,  2752,  2816,  2880,  2944,  3008,
      3072,  3136,  3200,  3264,  3328,  3392,  3456,  3520,
      3584,  3648,  3712,  3776,  3840,  3904,  3968,  4032,
    /* Moderate positive (step 256) */
      4096,  4352,  4608,  4864,  5120,  5376,  5632,  5888,
      6144,  6400,  6656,  6912,  7168,  7424,  7680,  7936,
      8192,  8448,  8704,  8960,  9216,  9472,  9728,  9984,
     10240, 10496, 10752, 11008, 11264, 11520, 11776, 12032,
     12288, 12544, 12800, 13056, 13312, 13568, 13824, 14080,
     14336, 14592, 14848, 15104, 15360, 15616, 15872, 16128,
    /* Large positive (step 1024) */
     16384, 17408, 18432, 19456, 20480, 21504, 22528, 23552,
     24576, 25600, 26624, 27648, 28672, 29696, 30720, 31744,
    /* Large negative (step 1024) */
    -32768,-31744,-30720,-29696,-28672,-27648,-26624,-25600,
    -24576,-23552,-22528,-21504,-20480,-19456,-18432,-17408,
    /* Moderate negative (step 256) */
    -16384,-16128,-15872,-15616,-15360,-15104,-14848,-14592,
    -14336,-14080,-13824,-13568,-13312,-13056,-12800,-12544,
    -12288,-12032,-11776,-11520,-11264,-11008,-10752,-10496,
    -10240, -9984, -9728, -9472, -9216, -8960, -8704, -8448,
     -8192, -7936, -7680, -7424, -7168, -6912, -6656, -6400,
     -6144, -5888, -5632, -5376, -5120, -4864, -4608, -4352,
    /* Near zero negative (step 64) */
     -4096, -4032, -3968, -3904, -3840, -3776, -3712, -3648,
     -3584, -3520, -3456, -3392, -3328, -3264, -3200, -3136,
     -3072, -3008, -2944, -2880, -2816, -2752, -2688, -2624,
     -2560, -2496, -2432, -2368, -2304, -2240, -2176, -2112,
     -2048, -1984, -1920, -1856, -1792, -1728, -1664, -1600,
     -1536, -1472, -1408, -1344, -1280, -1216, -1152, -1088,
     -1024,  -960,  -896,  -832,  -768,  -704,  -640,  -576,
      -512,  -448,  -384,  -320,  -256,  -192,  -128,   -64,
};

/* Encoder segment classification: (sample >> 6) + 8 → group */
static const uint8_t NLPCM_SEGMENT[16] = {
    0, 0, 0, 0,    /* large negative  (>>4) */
    1, 1, 1,        /* moderate negative (>>2) */
    2, 2,           /* near zero (no shift) */
    3, 3, 3,        /* moderate positive (>>2) */
    4, 4, 4, 4,     /* large positive (>>4) */
};


/* ================================================================
 * §1  Tables: Step Sizes
 *
 * Each method bundles its codec parameters into one struct so that
 * the encode/decode paths can be written generically.
 * ================================================================ */

typedef enum {
    CODEC_ADPCM,            /* Successive-approximation ADPCM           */
    CODEC_NONLINEAR_PCM,    /* Segmented companding                     */
    CODEC_8BIT_PCM,         /* Simple 8-bit truncation / expansion      */
    CODEC_16BIT_PCM,        /* Passthrough                              */
} CodecFamily;

typedef struct {
    const char    *name;
    CodecFamily    family;

    /* ADPCM parameters (ignored for PCM families) */
    int            total_bits;          /* Encoded bits per sample (sign + magnitude) */
    uint8_t        sign_mask;           /* Bitmask for the sign bit in encoded byte   */
    uint8_t        encoded_mask;        /* Valid-bits mask for encoded byte            */
    int            max_step_index;      /* Upper bound for step index clamping         */
    int32_t        clamp_hi;            /* Sample value upper clamp                   */
    int32_t        clamp_lo;            /* Sample value lower clamp                   */
    int            prescale_shift;      /* Right-shift on input, left-shift on output  */

    /* Pointers to per-method tables (NULL for PCM families) */
    const int32_t *step_sizes;          /* Step size table [0 .. max_step_index]       */
    const int16_t *step_adjusts;        /* Step adjust table [0 .. max_magnitude]      */
} MethodDescriptor;

/* Forward declarations of tables (defined in §2 and §3) */


/*
 * Method table, indexed by external API index (0–9).
 *
 * The external ordering matches the original DLL's indirection table.
 */
static const MethodDescriptor METHODS[ADPCM_NUM_METHODS] = {
    /* 0: 4-bit ADPCM1 — reduced precision variant */
    { "4bit ADPCM1", CODEC_ADPCM,
      .total_bits = 4, .sign_mask = 0x08, .encoded_mask = 0x0F,
      .max_step_index = 48, .clamp_hi = 0x07FF, .clamp_lo = -0x0800,
      .prescale_shift = 4,
      .step_sizes = STEP_SIZE_ADPCM1, .step_adjusts = STEP_ADJUST_ADPCM1 },

    /* 1: 2-bit ADPCM2 — maximum compression, minimum quality */
    { "2bit ADPCM2", CODEC_ADPCM,
      .total_bits = 2, .sign_mask = 0x02, .encoded_mask = 0x03,
      .max_step_index = 90, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_4BIT, .step_adjusts = STEP_ADJUST_ADPCM2_2BIT },

    /* 2: 4-bit ADPCM2 — the workhorse, good quality at 4:1 */
    { "4bit ADPCM2", CODEC_ADPCM,
      .total_bits = 4, .sign_mask = 0x08, .encoded_mask = 0x0F,
      .max_step_index = 90, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_4BIT, .step_adjusts = STEP_ADJUST_ADPCM2_4BIT },

    /* 3: 5-bit ADPCM2 */
    { "5bit ADPCM2", CODEC_ADPCM,
      .total_bits = 5, .sign_mask = 0x10, .encoded_mask = 0x1F,
      .max_step_index = 81, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_5BIT, .step_adjusts = STEP_ADJUST_ADPCM2_5BIT },

    /* 4: 6-bit ADPCM2 */
    { "6bit ADPCM2", CODEC_ADPCM,
      .total_bits = 6, .sign_mask = 0x20, .encoded_mask = 0x3F,
      .max_step_index = 71, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_6BIT, .step_adjusts = STEP_ADJUST_ADPCM2_6BIT },

    /* 5: 7-bit ADPCM2 */
    { "7bit ADPCM2", CODEC_ADPCM,
      .total_bits = 7, .sign_mask = 0x40, .encoded_mask = 0x7F,
      .max_step_index = 63, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_7BIT, .step_adjusts = STEP_ADJUST_ADPCM2_7BIT },

    /* 6: 8-bit ADPCM2 — best quality ADPCM, 2:1 compression */
    { "8bit ADPCM2", CODEC_ADPCM,
      .total_bits = 8, .sign_mask = 0x80, .encoded_mask = 0xFF,
      .max_step_index = 63, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = STEP_SIZE_ADPCM2_7BIT, .step_adjusts = STEP_ADJUST_ADPCM2_8BIT },
      /* Note: 8-bit shares the same step sizes as 7-bit */

    /* 7: Non-linear PCM */
    { "Non-liner PCM", CODEC_NONLINEAR_PCM,
      .total_bits = 8, .sign_mask = 0, .encoded_mask = 0xFF,
      .max_step_index = 0, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 6,
      .step_sizes = NULL, .step_adjusts = NULL },

    /* 8: 8-bit PCM — trivial unsigned↔signed conversion */
    { "8bit PCM", CODEC_8BIT_PCM,
      .total_bits = 8, .sign_mask = 0, .encoded_mask = 0xFF,
      .max_step_index = 0, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 8,
      .step_sizes = NULL, .step_adjusts = NULL },

    /* 9: 16-bit PCM — passthrough, no compression */
    { "16bit PCM", CODEC_16BIT_PCM,
      .total_bits = 16, .sign_mask = 0, .encoded_mask = 0xFF,
      .max_step_index = 0, .clamp_hi = 0x7FFF, .clamp_lo = -0x8000,
      .prescale_shift = 0,
      .step_sizes = NULL, .step_adjusts = NULL },
};


/* ================================================================
 * §5  Helpers
 * ================================================================ */

static int32_t clamp(int32_t value, int32_t lo, int32_t hi)
{
    if (value > hi) return hi;
    if (value < lo) return lo;
    return value;
}

static int16_t clamp_step_index(int32_t index, int max_index)
{
    if (index < 0) return 0;
    if (index > max_index) return (int16_t)max_index;
    return (int16_t)index;
}


/* ================================================================
 * §6  ADPCM Core Encode / Decode
 *
 * The algorithm is successive approximation: the difference between
 * the current sample and the previous reconstruction is binary-searched
 * against a halving step size, producing a sign bit followed by
 * N−1 magnitude bits.
 * ================================================================ */

/*
 * Encode one sample.
 *
 * Input:  ch->predicted contains the (prescaled) input sample.
 * Output: ch->predicted updated with the reconstructed sample (postscaled).
 *         ch->encoded_byte contains the encoded code.
 *         ch->step_index and ch->accumulator updated.
 */
static void adpcm_encode_sample(const MethodDescriptor *m, AdpcmChannelState *ch)
{
    /* Prescale to internal precision */
    int32_t sample = ch->predicted >> m->prescale_shift;

    /* Look up current step size */
    int32_t step = m->step_sizes[ch->step_index];

    /* Prediction error */
    int32_t diff = sample - ch->accumulator;
    diff = clamp(diff, m->clamp_lo, m->clamp_hi);
    int32_t abs_diff = (diff < 0) ? -diff : diff;

    /* Sign bit (MSB of encoded byte) */
    int direction = (sample >= ch->accumulator) ? 1 : -1;
    ch->encoded_byte = (direction < 0) ? 1 : 0;

    /* Successive approximation: magnitude bits, MSB first */
    int mag_bits = m->total_bits - 1;
    for (int i = 0; i < mag_bits; i++) {
        ch->encoded_byte <<= 1;

        int emit = (direction == 1) ? (abs_diff >= step)
                                    : (abs_diff >  step);
        if (emit) {
            ch->encoded_byte |= 1;
            ch->accumulator += direction * step;
            abs_diff -= step;
        }

        step >>= 1;
    }

    /* Half-step correction: centres reconstruction between levels */
    ch->accumulator += direction * step;
    ch->accumulator = clamp(ch->accumulator, m->clamp_lo, m->clamp_hi);

    /* Update step index from magnitude */
    uint8_t magnitude = ch->encoded_byte & (uint8_t)~m->sign_mask;
    int32_t new_index = (int32_t)ch->step_index + m->step_adjusts[magnitude];
    ch->step_index = clamp_step_index(new_index, m->max_step_index);

    /* Postscale the reconstructed sample back to 16-bit range */
    ch->predicted = ch->accumulator << m->prescale_shift;
}

/*
 * Decode one sample.
 *
 * Input:  ch->encoded_byte contains the code to decode.
 * Output: ch->predicted set to the reconstructed sample (postscaled).
 *         ch->step_index and ch->accumulator updated.
 */
static void adpcm_decode_sample(const MethodDescriptor *m, AdpcmChannelState *ch)
{
    int32_t step = m->step_sizes[ch->step_index];
    uint8_t code = ch->encoded_byte;

    /* Direction from sign bit */
    int direction = (code & m->sign_mask) ? -1 : 1;

    /* Reconstruct from magnitude bits, MSB to LSB */
    int mag_bits = m->total_bits - 1;
    int32_t code_signed = (int32_t)(int8_t)code;  /* sign-extend for SAR */
    for (int i = mag_bits - 1; i >= 0; i--) {
        int bit = (code_signed >> i) & 1;
        ch->accumulator += bit * step * direction;
        step >>= 1;
    }

    /* Half-step correction */
    ch->accumulator += direction * step;

    /* Update step index */
    uint8_t magnitude = code & (uint8_t)~m->sign_mask;
    int32_t new_index = (int32_t)ch->step_index + m->step_adjusts[magnitude];
    ch->step_index = clamp_step_index(new_index, m->max_step_index);

    /* Clamp and postscale */
    ch->accumulator = clamp(ch->accumulator, m->clamp_lo, m->clamp_hi);
    ch->predicted = ch->accumulator << m->prescale_shift;
}


/* ================================================================
 * §7  Non-Linear PCM Encode / Decode
 *
 * Encoding classifies the prescaled sample into one of five
 * amplitude groups, then applies a group-specific shift and bias
 * to produce a single byte. Decoding is a simple table lookup.
 * ================================================================ */

static void nlpcm_encode_sample(AdpcmChannelState *ch)
{
    int32_t s = ch->predicted >> 6;   /* prescale */
    int segment = (s >> 6) + 8;

    if (segment < 0 || segment > 15) return;

    uint8_t lo;
    switch (NLPCM_SEGMENT[segment]) {
    case 0:  /* large negative */
        s >>= 4; lo = (uint8_t)s; ch->encoded_byte = lo - 0x60;
        ch->predicted = (s << 4) << 6; break;
    case 1:  /* moderate negative */
        s >>= 2; lo = (uint8_t)s; ch->encoded_byte = lo - 0x30;
        ch->predicted = (s << 2) << 6; break;
    case 2:  /* near zero */
        ch->encoded_byte = (uint8_t)(s & 0xFF);
        ch->predicted = s << 6; break;
    case 3:  /* moderate positive */
        s >>= 2; lo = (uint8_t)s; ch->encoded_byte = lo + 0x30;
        ch->predicted = (s << 2) << 6; break;
    case 4:  /* large positive */
        s >>= 4; lo = (uint8_t)s; ch->encoded_byte = lo + 0x60;
        ch->predicted = (s << 4) << 6; break;
    }
}

static void nlpcm_decode_sample(AdpcmChannelState *ch)
{
    int32_t val = (int32_t)NLPCM_DECOMPRESS[ch->encoded_byte];
    ch->accumulator = val;
    ch->predicted = val;
}


/* ================================================================
 * §8  Top-Level Encode / Decode / Evaluate
 *
 * These handle PCM format conversion (8-bit unsigned ↔ signed,
 * bit depth scaling) and dispatch to the correct codec family.
 * ================================================================ */

/* Load a PCM sample into ch->predicted (16-bit signed internal) */
static void load_pcm_sample(const uint8_t *buf, uint32_t idx,
                            uint16_t bits_per_sample, AdpcmChannelState *ch)
{
    if (bits_per_sample == 16) {
        const int16_t *p = (const int16_t *)(buf + idx * 2);
        ch->predicted = (int32_t)*p;
    } else {
        /* 8-bit unsigned → signed, then scale to 16-bit range */
        uint8_t b = buf[idx] ^ 0x80;
        ch->predicted = ((int32_t)(int8_t)b) << 8;
    }
}

/* Store ch->predicted as a PCM sample */
static void store_pcm_sample(uint8_t *buf, uint32_t idx,
                             uint16_t bits_per_sample, const AdpcmChannelState *ch)
{
    if (bits_per_sample == 16) {
        int16_t *p = (int16_t *)(buf + idx * 2);
        *p = (int16_t)ch->predicted;
    } else {
        int8_t val = (int8_t)(ch->predicted >> 8);
        buf[idx] = (uint8_t)(val ^ 0x80);
    }
}


/* ================================================================
 * §9  Public API
 * ================================================================ */

int adpcm_get_num_methods(void) { return ADPCM_NUM_METHODS; }

const char *adpcm_get_method_name(int method)
{
    if (method < 0 || method >= ADPCM_NUM_METHODS) return NULL;
    return METHODS[method].name;
}

void adpcm_reset(AdpcmContext *ctx, int method,
                  uint16_t bits_per_sample, uint16_t num_channels)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->method = (method >= 0 && method < ADPCM_NUM_METHODS) ? method : 0;
    ctx->bits_per_sample = bits_per_sample;
    ctx->num_channels = (num_channels > ADPCM_MAX_CHANNELS)
                        ? ADPCM_MAX_CHANNELS : num_channels;
}


uint32_t adpcm_encode(AdpcmContext *ctx,
                       const uint8_t *pcm_in, uint8_t *out,
                       uint32_t pcm_byte_count)
{
    const MethodDescriptor *m = &METHODS[ctx->method];
    uint32_t bps = ctx->bits_per_sample >> 3;
    uint32_t total = pcm_byte_count / bps;
    uint32_t idx = 0;

    while (idx < total) {
        for (int ch = 0; ch < ctx->num_channels && idx < total; ch++, idx++) {
            AdpcmChannelState *cs = &ctx->enc[ch];

            switch (m->family) {
            case CODEC_ADPCM:
                load_pcm_sample(pcm_in, idx, ctx->bits_per_sample, cs);
                adpcm_encode_sample(m, cs);
                out[idx] = cs->encoded_byte;
                break;

            case CODEC_NONLINEAR_PCM:
                load_pcm_sample(pcm_in, idx, ctx->bits_per_sample, cs);
                nlpcm_encode_sample(cs);
                out[idx] = cs->encoded_byte;
                break;

            case CODEC_8BIT_PCM:
                if (ctx->bits_per_sample == 16) {
                    const int16_t *p = (const int16_t *)(pcm_in + idx * 2);
                    out[idx] = (uint8_t)(*p >> 8);
                } else {
                    out[idx] = pcm_in[idx] ^ 0x80;
                }
                break;

            case CODEC_16BIT_PCM:
                if (ctx->bits_per_sample == 16) {
                    ((int16_t *)out)[idx] = ((const int16_t *)pcm_in)[idx];
                } else {
                    uint8_t b = pcm_in[idx] ^ 0x80;
                    ((int16_t *)out)[idx] = (int16_t)((uint16_t)b << 8);
                }
                break;
            }
        }
    }
    return idx;
}


uint32_t adpcm_decode(AdpcmContext *ctx,
                       const uint8_t *in, uint8_t *pcm_out,
                       uint32_t sample_count)
{
    const MethodDescriptor *m = &METHODS[ctx->method];
    uint32_t idx = 0;

    while (idx < sample_count) {
        for (int ch = 0; ch < ctx->num_channels && idx < sample_count; ch++, idx++) {
            AdpcmChannelState *cs = &ctx->dec[ch];

            switch (m->family) {
            case CODEC_ADPCM:
                cs->encoded_byte = in[idx] & m->encoded_mask;
                adpcm_decode_sample(m, cs);
                store_pcm_sample(pcm_out, idx, ctx->bits_per_sample, cs);
                break;

            case CODEC_NONLINEAR_PCM:
                cs->encoded_byte = in[idx];
                nlpcm_decode_sample(cs);
                store_pcm_sample(pcm_out, idx, ctx->bits_per_sample, cs);
                break;

            case CODEC_8BIT_PCM:
                if (ctx->bits_per_sample == 16)
                    ((int16_t *)pcm_out)[idx] = (int16_t)((uint16_t)in[idx] << 8);
                else
                    pcm_out[idx] = in[idx] ^ 0x80;
                break;

            case CODEC_16BIT_PCM:
                if (ctx->bits_per_sample == 16)
                    ((int16_t *)pcm_out)[idx] = ((const int16_t *)in)[idx];
                else {
                    pcm_out[idx] = (uint8_t)((int8_t)(((const int16_t *)in)[idx] >> 8) ^ 0x80);
                }
                break;
            }
        }
    }
    return idx;
}


uint32_t adpcm_evaluate(AdpcmContext *ctx, uint8_t *pcm_buf, uint32_t byte_count)
{
    const MethodDescriptor *m = &METHODS[ctx->method];
    uint32_t bps = ctx->bits_per_sample >> 3;
    uint32_t total = byte_count / bps;
    uint32_t idx = 0;

    while (idx < total) {
        for (int ch = 0; ch < ctx->num_channels && idx < total; ch++, idx++) {
            AdpcmChannelState *cs = &ctx->enc[ch];

            switch (m->family) {
            case CODEC_ADPCM:
            case CODEC_NONLINEAR_PCM:
                load_pcm_sample(pcm_buf, idx, ctx->bits_per_sample, cs);
                if (m->family == CODEC_ADPCM)
                    adpcm_encode_sample(m, cs);
                else
                    nlpcm_encode_sample(cs);
                store_pcm_sample(pcm_buf, idx, ctx->bits_per_sample, cs);
                break;

            case CODEC_8BIT_PCM:
                if (ctx->bits_per_sample == 16)
                    *(uint8_t *)(pcm_buf + idx * 2) = 0;
                break;

            default:
                break;
            }
        }
    }
    return idx;
}


uint32_t adpcm_return_bytes(const AdpcmContext *ctx, int direction, uint32_t count)
{
    const MethodDescriptor *m = &METHODS[ctx->method];
    uint32_t bps = (uint32_t)ctx->bits_per_sample >> 3;

    if (m->family == CODEC_16BIT_PCM)
        return (count / bps) * 2;

    if (direction == ADPCM_DIRECTION_ENCODE)
        return count / bps;
    else
        return bps * count;
}
