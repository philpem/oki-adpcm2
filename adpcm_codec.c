/*
 * adpcm_codec.c — Reconstructed ADPCM Codec
 *
 * Reverse-engineered from a Windows DLL using Ghidra.
 * Standalone reimplementation — no dependencies beyond libc.
 *
 * Original DLL layout:
 *   Entry point at 0x10005020 (_DllMainCRTStartup)
 *   Code at 0x10001000–0x10005xxx
 *   Tables at 0x1003b000–0x1003d900
 *   Context at 0x1004dc88
 *
 * Exported API: adpcmGetNumMethod, adpcmGetMethod, adpcmReset,
 *               adpcmEva, adpcmEnc, adpcmDec, adpcmReturnBytes
 */

#include "adpcm_codec.h"
#include <string.h>

/* ================================================================
 * Constants
 * ================================================================ */

#define MAX_STEP_INDEX    90    /* Largest step index across all methods   */
#define STEP_TABLE_COLS   16    /* Columns per row (one per method slot)   */
#define STEP_TABLE_ROWS   91    /* Rows in step size table (indices 0–90)  */
#define ADJUST_TABLE_ROWS 128   /* Rows in adjustment table (magnitudes)   */


/* ================================================================
 * Method Dispatch Groups
 *
 * The original DLL uses a two-level dispatch: method code → group,
 * then group → code path. This reduces 14 methods to 6 groups.
 * ================================================================ */

typedef enum {
    GROUP_ADPCM   = 0,    /* ADPCM2 codes 0–5, also groups 2 & 4   */
    GROUP_8BIT    = 1,    /* 8-bit PCM (code 6)                     */
    GROUP_NLPCM   = 2,    /* Non-linear PCM (code 7), same path as 0 for enc/dec */
    GROUP_16BIT   = 3,    /* 16-bit PCM (code 8)                    */
    GROUP_2BIT    = 4,    /* 2-bit ADPCM2 (code 13), same as 0      */
    GROUP_NOOP    = 5,    /* G.726 codes 9–12 — not implemented      */
} DispatchGroup;

static const uint8_t METHOD_TO_GROUP[ADPCM_NUM_INTERNAL_METHODS] = {
    /*  0: 4bA2 */ 0,  /*  1: 5bA2 */ 0,  /*  2: 6bA2 */ 0,
    /*  3: 7bA2 */ 0,  /*  4: 8bA2 */ 0,  /*  5: 4bA1 */ 0,
    /*  6: 8bPCM*/ 1,  /*  7: NLPCM*/ 2,  /*  8:16bPCM*/ 3,
    /*  9: G726 */ 5,  /* 10: G726 */ 5,  /* 11: G726 */ 5,
    /* 12: G726 */ 5,  /* 13: 2bA2 */ 4,
};


/* ================================================================
 * Method Name Strings
 * ================================================================ */

static const char *const INTERNAL_METHOD_NAMES[ADPCM_NUM_INTERNAL_METHODS] = {
    "4bit ADPCM2",      /*  0 */
    "5bit ADPCM2",      /*  1 */
    "6bit ADPCM2",      /*  2 */
    "7bit ADPCM2",      /*  3 */
    "8bit ADPCM2",      /*  4 */
    "4bit ADPCM1",      /*  5 */
    "8bit PCM",         /*  6 */
    "Non-liner PCM",    /*  7  — typo preserved from original DLL */
    "16bit PCM",        /*  8 */
    "G726 2bit",        /*  9 */
    "G726 3bit",        /* 10 */
    "G726 4bit",        /* 11 */
    "G726 5bit",        /* 12 */
    "2bit ADPCM2",      /* 13 */
};

/* External index (0–9) → internal code mapping */
static const int8_t EXTERNAL_TO_INTERNAL[ADPCM_NUM_EXTERNAL_METHODS] = {
    5,    /* 0 → "4bit ADPCM1"   */
    13,   /* 1 → "2bit ADPCM2"   */
    0,    /* 2 → "4bit ADPCM2"   */
    1,    /* 3 → "5bit ADPCM2"   */
    2,    /* 4 → "6bit ADPCM2"   */
    3,    /* 5 → "7bit ADPCM2"   */
    4,    /* 6 → "8bit ADPCM2"   */
    7,    /* 7 → "Non-liner PCM" */
    6,    /* 8 → "8bit PCM"      */
    8,    /* 9 → "16bit PCM"     */
};


/* ================================================================
 * Per-Method Configuration Tables
 *
 * Each table has 14 entries indexed by internal method code.
 * ================================================================ */

/* Total bits per encoded sample (sign + magnitude) */
static const uint8_t BITS_PER_METHOD[ADPCM_NUM_INTERNAL_METHODS] = {
 /* 4bA2  5bA2  6bA2  7bA2  8bA2  4bA1  8bPCM NLPCM 16bPCM G2b   G3b   G4b   G5b   2bA2 */
    4,    5,    6,    7,    8,    4,    8,    8,    16,   2,    3,    4,    5,    2,
};

/* Valid bit mask for encoded byte — strips padding bits from bitstream */
static const uint8_t ENCODED_BYTE_MASK[ADPCM_NUM_INTERNAL_METHODS] = {
    0x0F, 0x1F, 0x3F, 0x7F, 0xFF, 0x0F, 0xFF, 0xFF,
    0xFF, 0x03, 0x07, 0x0F, 0x1F, 0x03,
};

/* Sign bit mask — MSB of the encoded value */
static const uint8_t SIGN_MASK[ADPCM_NUM_INTERNAL_METHODS] = {
    0x08, 0x10, 0x20, 0x40, 0x80, 0x08, 0x80, 0x80,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x02,
};

/* Maximum step index per method */
static const int16_t MAX_STEP_IDX[ADPCM_NUM_INTERNAL_METHODS] = {
    90, 81, 71, 63, 63, 48, 90, 90, 90, 90, 90, 90, 90, 90,
};


/* ================================================================
 * Step Size Table
 *
 * 91 rows × 16 columns of int32.
 * Indexed: stepSizeTable[stepIndex * 16 + methodCode]
 *
 * Growth rate: ~1.08× per row (doubles every ~9 rows).
 * Only ADPCM columns (0–5, 13) are non-zero.
 * ================================================================ */

static const int32_t STEP_SIZE_TABLE[STEP_TABLE_ROWS * STEP_TABLE_COLS] = {
 /* row, col:   0      1      2      3      4      5      6      7      8      9     10     11     12     13     14     15  */
 /* [ 0] */    16,    32,    64,   128,   128,    16,     0,     0,     0,     0,     0,     0,     0,    16,     0,     0,
 /* [ 1] */    17,    34,    69,   138,   138,    17,     0,     0,     0,     0,     0,     0,     0,    17,     0,     0,
 /* [ 2] */    18,    37,    74,   149,   149,    19,     0,     0,     0,     0,     0,     0,     0,    18,     0,     0,
 /* [ 3] */    20,    40,    80,   161,   161,    21,     0,     0,     0,     0,     0,     0,     0,    20,     0,     0,
 /* [ 4] */    21,    43,    87,   174,   174,    23,     0,     0,     0,     0,     0,     0,     0,    21,     0,     0,
 /* [ 5] */    23,    47,    94,   188,   188,    25,     0,     0,     0,     0,     0,     0,     0,    23,     0,     0,
 /* [ 6] */    25,    50,   101,   203,   203,    28,     0,     0,     0,     0,     0,     0,     0,    25,     0,     0,
 /* [ 7] */    27,    54,   109,   219,   219,    31,     0,     0,     0,     0,     0,     0,     0,    27,     0,     0,
 /* [ 8] */    29,    59,   118,   236,   236,    34,     0,     0,     0,     0,     0,     0,     0,    29,     0,     0,
 /* [ 9] */    31,    63,   127,   255,   255,    37,     0,     0,     0,     0,     0,     0,     0,    31,     0,     0,
 /* [10] */    34,    69,   138,   276,   276,    41,     0,     0,     0,     0,     0,     0,     0,    34,     0,     0,
 /* [11] */    37,    74,   149,   298,   298,    45,     0,     0,     0,     0,     0,     0,     0,    37,     0,     0,
 /* [12] */    40,    80,   161,   322,   322,    50,     0,     0,     0,     0,     0,     0,     0,    40,     0,     0,
 /* [13] */    43,    87,   174,   348,   348,    55,     0,     0,     0,     0,     0,     0,     0,    43,     0,     0,
 /* [14] */    46,    93,   187,   375,   375,    60,     0,     0,     0,     0,     0,     0,     0,    46,     0,     0,
 /* [15] */    50,   101,   203,   406,   406,    66,     0,     0,     0,     0,     0,     0,     0,    50,     0,     0,
 /* [16] */    54,   109,   219,   438,   438,    73,     0,     0,     0,     0,     0,     0,     0,    54,     0,     0,
 /* [17] */    59,   118,   236,   473,   473,    80,     0,     0,     0,     0,     0,     0,     0,    59,     0,     0,
 /* [18] */    63,   127,   255,   511,   511,    88,     0,     0,     0,     0,     0,     0,     0,    63,     0,     0,
 /* [19] */    69,   138,   276,   552,   552,    97,     0,     0,     0,     0,     0,     0,     0,    69,     0,     0,
 /* [20] */    74,   149,   298,   596,   596,   107,     0,     0,     0,     0,     0,     0,     0,    74,     0,     0,
 /* [21] */    80,   161,   322,   644,   644,   118,     0,     0,     0,     0,     0,     0,     0,    80,     0,     0,
 /* [22] */    86,   173,   347,   695,   695,   130,     0,     0,     0,     0,     0,     0,     0,    86,     0,     0,
 /* [23] */    93,   187,   375,   751,   751,   143,     0,     0,     0,     0,     0,     0,     0,    93,     0,     0,
 /* [24] */   101,   202,   405,   811,   811,   157,     0,     0,     0,     0,     0,     0,     0,   101,     0,     0,
 /* [25] */   109,   219,   438,   876,   876,   173,     0,     0,     0,     0,     0,     0,     0,   109,     0,     0,
 /* [26] */   118,   236,   473,   946,   946,   190,     0,     0,     0,     0,     0,     0,     0,   118,     0,     0,
 /* [27] */   127,   255,   511,  1022,  1022,   209,     0,     0,     0,     0,     0,     0,     0,   127,     0,     0,
 /* [28] */   138,   276,   552,  1104,  1104,   230,     0,     0,     0,     0,     0,     0,     0,   138,     0,     0,
 /* [29] */   149,   298,   596,  1192,  1192,   253,     0,     0,     0,     0,     0,     0,     0,   149,     0,     0,
 /* [30] */   161,   322,   644,  1288,  1288,   279,     0,     0,     0,     0,     0,     0,     0,   161,     0,     0,
 /* [31] */   173,   347,   695,  1391,  1391,   307,     0,     0,     0,     0,     0,     0,     0,   173,     0,     0,
 /* [32] */   187,   375,   751,  1502,  1502,   337,     0,     0,     0,     0,     0,     0,     0,   187,     0,     0,
 /* [33] */   202,   405,   811,  1622,  1622,   371,     0,     0,     0,     0,     0,     0,     0,   202,     0,     0,
 /* [34] */   219,   438,   876,  1752,  1752,   408,     0,     0,     0,     0,     0,     0,     0,   219,     0,     0,
 /* [35] */   236,   473,   946,  1892,  1892,   449,     0,     0,     0,     0,     0,     0,     0,   236,     0,     0,
 /* [36] */   255,   510,  1021,  2043,  2043,   494,     0,     0,     0,     0,     0,     0,     0,   255,     0,     0,
 /* [37] */   275,   551,  1103,  2207,  2207,   544,     0,     0,     0,     0,     0,     0,     0,   275,     0,     0,
 /* [38] */   298,   596,  1192,  2384,  2384,   598,     0,     0,     0,     0,     0,     0,     0,   298,     0,     0,
 /* [39] */   321,   643,  1287,  2574,  2574,   658,     0,     0,     0,     0,     0,     0,     0,   321,     0,     0,
 /* [40] */   347,   695,  1390,  2780,  2780,   724,     0,     0,     0,     0,     0,     0,     0,   347,     0,     0,
 /* [41] */   375,   750,  1501,  3003,  3003,   796,     0,     0,     0,     0,     0,     0,     0,   375,     0,     0,
 /* [42] */   405,   810,  1621,  3243,  3243,   876,     0,     0,     0,     0,     0,     0,     0,   405,     0,     0,
 /* [43] */   437,   875,  1751,  3502,  3502,   963,     0,     0,     0,     0,     0,     0,     0,   437,     0,     0,
 /* [44] */   472,   945,  1891,  3783,  3783,  1060,     0,     0,     0,     0,     0,     0,     0,   472,     0,     0,
 /* [45] */   510,  1021,  2042,  4085,  4085,  1166,     0,     0,     0,     0,     0,     0,     0,   510,     0,     0,
 /* [46] */   551,  1103,  2206,  4412,  4412,  1282,     0,     0,     0,     0,     0,     0,     0,   551,     0,     0,
 /* [47] */   595,  1191,  2382,  4765,  4765,  1411,     0,     0,     0,     0,     0,     0,     0,   595,     0,     0,
 /* [48] */   643,  1286,  2573,  5146,  5146,  1552,     0,     0,     0,     0,     0,     0,     0,   643,     0,     0,
 /* [49] */   694,  1389,  2779,  5558,  5558,     0,     0,     0,     0,     0,     0,     0,     0,   694,     0,     0,
 /* [50] */   750,  1500,  3001,  6003,  6003,     0,     0,     0,     0,     0,     0,     0,     0,   750,     0,     0,
 /* [51] */   810,  1620,  3241,  6483,  6483,     0,     0,     0,     0,     0,     0,     0,     0,   810,     0,     0,
 /* [52] */   875,  1750,  3501,  7002,  7002,     0,     0,     0,     0,     0,     0,     0,     0,   875,     0,     0,
 /* [53] */   945,  1890,  3781,  7562,  7562,     0,     0,     0,     0,     0,     0,     0,     0,   945,     0,     0,
 /* [54] */  1020,  2041,  4083,  8167,  8167,     0,     0,     0,     0,     0,     0,     0,     0,  1020,     0,     0,
 /* [55] */  1102,  2205,  4410,  8820,  8820,     0,     0,     0,     0,     0,     0,     0,     0,  1102,     0,     0,
 /* [56] */  1190,  2381,  4763,  9526,  9526,     0,     0,     0,     0,     0,     0,     0,     0,  1190,     0,     0,
 /* [57] */  1286,  2572,  5144, 10288, 10288,     0,     0,     0,     0,     0,     0,     0,     0,  1286,     0,     0,
 /* [58] */  1388,  2777,  5555, 11111, 11111,     0,     0,     0,     0,     0,     0,     0,     0,  1388,     0,     0,
 /* [59] */  1500,  3000,  6000, 12000, 12000,     0,     0,     0,     0,     0,     0,     0,     0,  1500,     0,     0,
 /* [60] */  1620,  3240,  6480, 12960, 12960,     0,     0,     0,     0,     0,     0,     0,     0,  1620,     0,     0,
 /* [61] */  1749,  3499,  6998, 13997, 13997,     0,     0,     0,     0,     0,     0,     0,     0,  1749,     0,     0,
 /* [62] */  1889,  3779,  7558, 15117, 15117,     0,     0,     0,     0,     0,     0,     0,     0,  1889,     0,     0,
 /* [63] */  2040,  4081,  8163, 16327, 16327,     0,     0,     0,     0,     0,     0,     0,     0,  2040,     0,     0,
 /* [64] */  2204,  4408,  8816,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  2204,     0,     0,
 /* [65] */  2380,  4760,  9521,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  2380,     0,     0,
 /* [66] */  2570,  5141, 10283,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  2570,     0,     0,
 /* [67] */  2776,  5553, 11106,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  2776,     0,     0,
 /* [68] */  2998,  5997, 11994,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  2998,     0,     0,
 /* [69] */  3238,  6477, 12954,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  3238,     0,     0,
 /* [70] */  3497,  6995, 13990,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  3497,     0,     0,
 /* [71] */  3777,  7555, 15110,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  3777,     0,     0,
 /* [72] */  4079,  8159,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  4079,     0,     0,
 /* [73] */  4406,  8812,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  4406,     0,     0,
 /* [74] */  4758,  9517,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  4758,     0,     0,
 /* [75] */  5139, 10278,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  5139,     0,     0,
 /* [76] */  5550, 11100,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  5550,     0,     0,
 /* [77] */  5994, 11988,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  5994,     0,     0,
 /* [78] */  6474, 12948,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  6474,     0,     0,
 /* [79] */  6991, 13983,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  6991,     0,     0,
 /* [80] */  7551, 15102,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  7551,     0,     0,
 /* [81] */  8155, 16310,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  8155,     0,     0,
 /* [82] */  8807,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  8807,     0,     0,
 /* [83] */  9512,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,  9512,     0,     0,
 /* [84] */ 10273,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 10273,     0,     0,
 /* [85] */ 11095,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 11095,     0,     0,
 /* [86] */ 11982,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 11982,     0,     0,
 /* [87] */ 12941,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 12941,     0,     0,
 /* [88] */ 13976,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 13976,     0,     0,
 /* [89] */ 15095,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 15095,     0,     0,
 /* [90] */ 16302,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,     0, 16302,     0,     0,
};

/* ================================================================
 * Step Index Adjustment Table
 *
 * 128 rows × 16 columns of int16.
 * Indexed: stepAdjustTable[magnitude * 16 + methodCode]
 *
 * Small magnitudes → negative adjustment (decrease step for quiet signals)
 * Large magnitudes → positive adjustment (increase step for transients)
 * ================================================================ */

static const int16_t STEP_ADJUST_TABLE[ADJUST_TABLE_ROWS * STEP_TABLE_COLS] = {
    /* [  0] */  -2,  -2,  -2,  -2,  -2,  -1,   0,   0,   0,   0,   0,   0,   0,  -2,   0,   0,
    /* [  1] */  -2,  -2,  -2,  -2,  -2,  -1,   0,   0,   0,   0,   0,   0,   0,   3,   0,   0,
    /* [  2] */  -2,  -2,  -2,  -2,  -2,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  3] */  -2,  -2,  -2,  -2,  -2,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  4] */   2,  -1,  -2,  -2,  -2,   2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  5] */   6,  -1,  -2,  -2,  -2,   4,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  6] */   9,  -1,  -2,  -2,  -2,   6,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  7] */  11,  -1,  -2,  -2,  -2,   8,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  8] */   0,   2,  -1,  -2,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [  9] */   0,   5,  -1,  -2,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 10] */   0,   7,  -1,  -2,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 11] */   0,   9,  -1,  -2,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 12] */   0,  11,  -1,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 13] */   0,  12,  -1,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 14] */   0,  14,  -1,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 15] */   0,  15,  -1,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 16] */   0,   0,   1,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 17] */   0,   0,   3,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 18] */   0,   0,   5,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 19] */   0,   0,   6,  -1,  -2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 20] */   0,   0,   9,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 21] */   0,   0,  10,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 22] */   0,   0,  12,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 23] */   0,   0,  14,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 24] */   0,   0,  16,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 25] */   0,   0,  18,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 26] */   0,   0,  19,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 27] */   0,   0,  21,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 28] */   0,   0,  23,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 29] */   0,   0,  25,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 30] */   0,   0,  27,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 31] */   0,   0,  28,  -1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 32] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 33] */   0,   0,   0,   1,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 34] */   0,   0,   0,   2,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 35] */   0,   0,   0,   3,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 36] */   0,   0,   0,   3,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 37] */   0,   0,   0,   4,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 38] */   0,   0,   0,   5,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 39] */   0,   0,   0,   6,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 40] */   0,   0,   0,   6,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 41] */   0,   0,   0,   7,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 42] */   0,   0,   0,   8,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 43] */   0,   0,   0,   9,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 44] */   0,   0,   0,   9,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 45] */   0,   0,   0,  10,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 46] */   0,   0,   0,  11,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 47] */   0,   0,   0,  12,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 48] */   0,   0,   0,  12,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 49] */   0,   0,   0,  13,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 50] */   0,   0,   0,  14,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 51] */   0,   0,   0,  15,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 52] */   0,   0,   0,  15,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 53] */   0,   0,   0,  16,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 54] */   0,   0,   0,  17,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 55] */   0,   0,   0,  18,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 56] */   0,   0,   0,  18,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 57] */   0,   0,   0,  19,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 58] */   0,   0,   0,  20,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 59] */   0,   0,   0,  21,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 60] */   0,   0,   0,  21,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 61] */   0,   0,   0,  22,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 62] */   0,   0,   0,  23,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 63] */   0,   0,   0,  24,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 64] */   0,   0,   0,  24,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 65] */   0,   0,   0,  25,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 66] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 67] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 68] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 69] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 70] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 71] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 72] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 73] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 74] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 75] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 76] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 77] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 78] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 79] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 80] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 81] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 82] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 83] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 84] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 85] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 86] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 87] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 88] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 89] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 90] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 91] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 92] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 93] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 94] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 95] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 96] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 97] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 98] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [ 99] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [100] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [101] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [102] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [103] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [104] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [105] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [106] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [107] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [108] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [109] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [110] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [111] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [112] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [113] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [114] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [115] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [116] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [117] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [118] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [119] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [120] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [121] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [122] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [123] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [124] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [125] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [126] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    /* [127] */   0,   0,   0,   0,  -1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};

/* ================================================================
 * Non-Linear PCM Decompanding Table
 *
 * 256 entries of int16, indexed by encoded byte.
 * 3-segment piecewise linear, symmetric around zero:
 *   Entries   0– 63: step   64  (fine, near zero +)
 *   Entries  64–111: step  256  (medium +)
 *   Entries 112–127: step 1024  (coarse +)
 *   Entries 128–143: step 1024  (coarse −)
 *   Entries 144–191: step  256  (medium −)
 *   Entries 192–255: step   64  (fine, near zero −)
 * ================================================================ */

static const int16_t NLPCM_DECOMPAND_TABLE[256] = {
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


/* NL PCM encoder: segment classification table (16 entries) */
static const uint8_t NLPCM_SEGMENT_TABLE[16] = {
    0, 0, 0, 0,   /* segments 0–3:   large negative  */
    1, 1, 1,       /* segments 4–6:   moderate negative */
    2, 2,          /* segments 7–8:   near zero */
    3, 3, 3,       /* segments 9–11:  moderate positive */
    4, 4, 4, 4,    /* segments 12–15: large positive */
};


/* ================================================================
 * Internal Helper Functions
 * ================================================================ */

/* Prescale: reduce sample precision for methods with narrower internal range */
static int32_t prescale_sample(int method, int32_t sample)
{
    switch (method) {
    case ADPCM_METHOD_4BIT_ADPCM1:   return sample >> 4;
    case ADPCM_METHOD_8BIT_PCM:      return sample >> 8;
    case ADPCM_METHOD_NONLINEAR_PCM: return sample >> 6;
    default:                          return sample;
    }
}

/* Postscale: restore sample to 16-bit range (inverse of prescale) */
static int32_t postscale_sample(int method, int32_t sample)
{
    switch (method) {
    case ADPCM_METHOD_4BIT_ADPCM1:   return sample << 4;
    case ADPCM_METHOD_8BIT_PCM:      return sample << 8;
    case ADPCM_METHOD_NONLINEAR_PCM: return sample << 6;
    default:                          return sample;
    }
}

/* Clamp a value to the internal precision range for the method */
static int32_t clamp_value(int method, int32_t value)
{
    int32_t hi, lo;
    if (method == ADPCM_METHOD_4BIT_ADPCM1) {
        hi =  0x07FF;   /* ±2047: 12-bit signed */
        lo = -0x0800;
    } else {
        hi =  0x7FFF;   /* ±32767: 16-bit signed */
        lo = -0x8000;
    }
    if (value > hi) return hi;
    if (value < lo) return lo;
    return value;
}

/* Clamp step index to valid range for the method */
static int16_t clamp_step_index(int method, int32_t index)
{
    if (index < 0) return 0;
    int16_t max_idx = MAX_STEP_IDX[method];
    if (index > max_idx) return max_idx;
    return (int16_t)index;
}

/* Get the dispatch group for a method code */
static int get_group(int method)
{
    if (method >= 0 && method < ADPCM_NUM_INTERNAL_METHODS)
        return METHOD_TO_GROUP[method];
    return GROUP_NOOP;
}

/* Check if a group uses the ADPCM encode/decode path */
static int is_adpcm_group(int group)
{
    return group == GROUP_ADPCM || group == GROUP_NLPCM || group == GROUP_2BIT;
}


/* ================================================================
 * Non-Linear PCM Encoder (Segmented Companding)
 * ================================================================ */

static void nlpcm_encode(AdpcmChannelState *ch)
{
    int32_t sample = ch->predicted;
    int segment = (sample >> 6) + 8;

    if (segment < 0 || segment > 15) return;

    int group = NLPCM_SEGMENT_TABLE[segment];
    uint8_t lo;

    switch (group) {
    case 2: /* Near zero: direct byte, no quantisation */
        ch->encoded_byte = (uint8_t)(sample & 0xFF);
        break;

    case 3: /* Moderate positive: >>2 then bias +0x30 */
        sample >>= 2;
        lo = (uint8_t)(sample & 0xFF);
        ch->encoded_byte = lo + 0x30;
        ch->predicted = sample << 2;
        break;

    case 1: /* Moderate negative: >>2 then bias −0x30 */
        sample >>= 2;
        lo = (uint8_t)(sample & 0xFF);
        ch->encoded_byte = lo - 0x30;
        ch->predicted = sample << 2;
        break;

    case 4: /* Large positive: >>4 then bias +0x60 */
        sample >>= 4;
        lo = (uint8_t)(sample & 0xFF);
        ch->encoded_byte = lo + 0x60;
        ch->predicted = sample << 4;
        break;

    case 0: /* Large negative: >>4 then bias −0x60 */
        sample >>= 4;
        lo = (uint8_t)(sample & 0xFF);
        ch->encoded_byte = lo - 0x60;
        ch->predicted = sample << 4;
        break;
    }
}


/* ================================================================
 * Core ADPCM Encode (One Sample)
 *
 * Successive approximation: encodes the difference between the
 * current sample and the previously reconstructed accumulator.
 * ================================================================ */

static void encode_one_sample(int method, AdpcmChannelState *ch)
{
    /* 1. Prescale input sample */
    ch->predicted = prescale_sample(method, ch->predicted);

    /* 2. Look up current step size */
    int32_t step_size = STEP_SIZE_TABLE[(int)ch->step_index * STEP_TABLE_COLS + method];

    /* 3. Compute and clamp the prediction error */
    int32_t diff = ch->predicted - ch->accumulator;
    diff = clamp_value(method, diff);
    int32_t abs_diff = (diff < 0) ? -diff : diff;

    /* 4. Encode sign bit */
    ch->encoded_byte = (ch->predicted < ch->accumulator) ? 1 : 0;
    int direction = (ch->predicted >= ch->accumulator) ? 1 : -1;

    /* 5. Successive approximation loop for magnitude bits */
    int total_bits = (int)BITS_PER_METHOD[method];

    for (int bit = 1; bit < total_bits; bit++) {
        ch->encoded_byte <<= 1;

        int emit = 0;
        if (direction == 1 && abs_diff >= step_size)
            emit = 1;
        else if (direction == -1 && abs_diff > step_size)
            emit = 1;

        if (emit) {
            ch->encoded_byte++;
            ch->accumulator += direction * step_size;
            abs_diff -= step_size;
        }

        /* Halve step size for next bit */
        step_size = (step_size + (step_size < 0 ? 1 : 0)) >> 1;
    }

    /* 6. Half-step correction */
    ch->accumulator += direction * step_size;
    ch->accumulator = clamp_value(method, ch->accumulator);

    /* 7. Update step index */
    uint8_t magnitude = ch->encoded_byte & (uint8_t)~SIGN_MASK[method];
    int16_t adjust = STEP_ADJUST_TABLE[(int)magnitude * STEP_TABLE_COLS + method];
    ch->step_index = clamp_step_index(method, (int32_t)ch->step_index + adjust);

    /* 8. Post-encode: update predicted sample based on method */
    int post_group = get_group(method);
    if (is_adpcm_group(post_group) && method != ADPCM_METHOD_NONLINEAR_PCM) {
        ch->predicted = postscale_sample(method, ch->accumulator);
    } else if (method == ADPCM_METHOD_NONLINEAR_PCM) {
        nlpcm_encode(ch);
        ch->predicted = postscale_sample(method, ch->predicted);
    }
}


/* ================================================================
 * Core ADPCM Decode (One Sample)
 *
 * Reconstructs the sample by applying each magnitude bit of the
 * encoded byte against the current step size.
 * ================================================================ */

static void decode_one_sample(int method, AdpcmChannelState *ch)
{
    /* Non-linear PCM: simple table lookup */
    if (method == ADPCM_METHOD_NONLINEAR_PCM) {
        int32_t val = (int32_t)NLPCM_DECOMPAND_TABLE[ch->encoded_byte];
        ch->accumulator = val;
        ch->predicted = val;
        return;
    }

    /* PCM / G.726: no-op */
    if (method == ADPCM_METHOD_8BIT_PCM || method >= ADPCM_METHOD_16BIT_PCM)
        return;

    /* ADPCM decode */
    int32_t step_size = STEP_SIZE_TABLE[(int)ch->step_index * STEP_TABLE_COLS + method];
    uint8_t encoded = ch->encoded_byte;

    /* Extract sign → direction */
    int direction = (encoded & SIGN_MASK[method]) ? -1 : 1;

    /* Magnitude bit loop: MSB to LSB */
    int16_t bit_pos = (int16_t)BITS_PER_METHOD[method] - 2;
    if (bit_pos >= 0) {
        int32_t enc_full = (int32_t)(int8_t)encoded;
        for (; bit_pos >= 0; bit_pos--) {
            int32_t bit = (enc_full >> bit_pos) & 1;
            ch->accumulator += bit * step_size * direction;
            step_size >>= 1;
        }
    }

    /* Half-step correction */
    ch->accumulator += direction * step_size;

    /* Update step index */
    uint32_t magnitude = (uint32_t)encoded & (uint32_t)(uint8_t)~SIGN_MASK[method];
    int16_t adjust = STEP_ADJUST_TABLE[magnitude * STEP_TABLE_COLS + method];
    ch->step_index = clamp_step_index(method, (int32_t)ch->step_index + adjust);

    /* Clamp and set output */
    ch->accumulator = clamp_value(method, ch->accumulator);
    ch->predicted = postscale_sample(method, ch->accumulator);
}


/* ================================================================
 * Public API
 * ================================================================ */

int adpcm_get_num_methods(void)
{
    return ADPCM_NUM_EXTERNAL_METHODS;
}

const char *adpcm_get_method_name(int external_index)
{
    if (external_index < 0 || external_index >= ADPCM_NUM_EXTERNAL_METHODS)
        return NULL;
    int code = EXTERNAL_TO_INTERNAL[external_index];
    return INTERNAL_METHOD_NAMES[code];
}

void adpcm_reset(AdpcmContext *ctx, int external_method_index,
                  uint16_t bits_per_sample, uint16_t num_channels)
{
    if (external_method_index < 0 || external_method_index >= ADPCM_NUM_EXTERNAL_METHODS)
        return;

    ctx->method_code = (uint8_t)EXTERNAL_TO_INTERNAL[external_method_index];
    ctx->bits_per_sample = bits_per_sample;
    ctx->num_channels = (num_channels > ADPCM_MAX_CHANNELS)
                        ? ADPCM_MAX_CHANNELS : num_channels;

    for (int i = 0; i < ADPCM_MAX_CHANNELS; i++) {
        ctx->enc_channels[i].predicted   = 0;
        ctx->enc_channels[i].step_index  = 0;
        ctx->enc_channels[i].encoded_byte = 0;
        ctx->enc_channels[i].accumulator = 0;
        ctx->dec_channels[i].predicted   = 0;
        ctx->dec_channels[i].step_index  = 0;
        ctx->dec_channels[i].encoded_byte = 0;
        ctx->dec_channels[i].accumulator = 0;
    }
}


uint32_t adpcm_encode(AdpcmContext *ctx,
                       const uint8_t *pcm_in, uint8_t *compressed_out,
                       uint32_t pcm_byte_count)
{
    int method = (int)(int8_t)ctx->method_code;
    uint32_t bps = ctx->bits_per_sample >> 3;
    uint32_t total_samples = pcm_byte_count / bps;
    uint32_t sample_idx = 0;

    while (sample_idx < total_samples) {
        for (int ch = 0; ch < ctx->num_channels && sample_idx < total_samples; ch++) {
            AdpcmChannelState *cs = &ctx->enc_channels[ch];
            int group = get_group(method);

            if (is_adpcm_group(group)) {
                /* Load sample into predicted */
                if (ctx->bits_per_sample == 16) {
                    const int16_t *p = (const int16_t *)(pcm_in + sample_idx * 2);
                    cs->predicted = (int32_t)*p;
                } else {
                    uint8_t b = pcm_in[sample_idx] ^ 0x80;
                    cs->predicted = ((int32_t)(int8_t)b) << 8;
                }

                encode_one_sample(method, cs);
                compressed_out[sample_idx] = cs->encoded_byte;

            } else if (group == GROUP_8BIT) {
                if (ctx->bits_per_sample == 16) {
                    const int16_t *p = (const int16_t *)(pcm_in + sample_idx * 2);
                    compressed_out[sample_idx] = (uint8_t)((int16_t)*p >> 8);
                } else {
                    compressed_out[sample_idx] = pcm_in[sample_idx] ^ 0x80;
                }

            } else if (group == GROUP_16BIT) {
                if (ctx->bits_per_sample == 16) {
                    int16_t *out = (int16_t *)(compressed_out + sample_idx * 2);
                    const int16_t *in = (const int16_t *)(pcm_in + sample_idx * 2);
                    *out = *in;
                } else {
                    uint8_t b = pcm_in[sample_idx] ^ 0x80;
                    int16_t *out = (int16_t *)(compressed_out + sample_idx * 2);
                    *out = (int16_t)((uint16_t)(uint8_t)b << 8);
                }
            }
            /* GROUP_NOOP: skip */

            sample_idx++;
        }
    }
    return sample_idx;
}


uint32_t adpcm_decode(AdpcmContext *ctx,
                       const uint8_t *compressed_in, uint8_t *pcm_out,
                       uint32_t sample_count)
{
    int method = (int)(int8_t)ctx->method_code;
    uint32_t sample_idx = 0;

    while (sample_idx < sample_count) {
        for (int ch = 0; ch < ctx->num_channels && sample_idx < sample_count; ch++) {
            AdpcmChannelState *cs = &ctx->dec_channels[ch];
            int group = get_group(method);

            if (is_adpcm_group(group)) {
                uint8_t mask = ENCODED_BYTE_MASK[method];
                cs->encoded_byte = compressed_in[sample_idx] & mask;

                decode_one_sample(method, cs);

                if (ctx->bits_per_sample == 16) {
                    int16_t *out = (int16_t *)(pcm_out + sample_idx * 2);
                    *out = (int16_t)cs->predicted;
                } else {
                    int8_t val = (int8_t)(cs->predicted >> 8);
                    pcm_out[sample_idx] = (uint8_t)(val ^ 0x80);
                }

            } else if (group == GROUP_8BIT) {
                if (ctx->bits_per_sample == 16) {
                    int16_t *out = (int16_t *)(pcm_out + sample_idx * 2);
                    *out = (int16_t)((uint16_t)compressed_in[sample_idx] << 8);
                } else {
                    pcm_out[sample_idx] = compressed_in[sample_idx] ^ 0x80;
                }

            } else if (group == GROUP_16BIT) {
                if (ctx->bits_per_sample == 16) {
                    int16_t *out = (int16_t *)(pcm_out + sample_idx * 2);
                    const int16_t *in = (const int16_t *)(compressed_in + sample_idx * 2);
                    *out = *in;
                } else {
                    const int16_t *in = (const int16_t *)(compressed_in + sample_idx * 2);
                    pcm_out[sample_idx] = (uint8_t)((int8_t)(*in >> 8) ^ 0x80);
                }
            }

            sample_idx++;
        }
    }
    return sample_idx;
}


uint32_t adpcm_evaluate(AdpcmContext *ctx, uint8_t *pcm_buf, uint32_t byte_count)
{
    int method = (int)(int8_t)ctx->method_code;
    uint32_t bps = ctx->bits_per_sample >> 3;
    uint32_t total_samples = byte_count / bps;
    uint32_t sample_idx = 0;

    while (sample_idx < total_samples) {
        for (int ch = 0; ch < ctx->num_channels && sample_idx < total_samples; ch++) {
            AdpcmChannelState *cs = &ctx->enc_channels[ch];
            int group = get_group(method);

            if (is_adpcm_group(group)) {
                if (ctx->bits_per_sample == 16) {
                    int16_t *p = (int16_t *)(pcm_buf + sample_idx * 2);
                    cs->predicted = (int32_t)*p;
                } else {
                    pcm_buf[sample_idx] ^= 0x80;
                    cs->predicted = ((int32_t)(int8_t)pcm_buf[sample_idx]) << 8;
                }

                encode_one_sample(method, cs);

                /* Write back reconstructed sample */
                if (ctx->bits_per_sample == 16) {
                    int16_t *p = (int16_t *)(pcm_buf + sample_idx * 2);
                    *p = (int16_t)cs->predicted;
                } else {
                    pcm_buf[sample_idx] = (uint8_t)((int8_t)(cs->predicted >> 8) ^ 0x80);
                }

            } else if (group == GROUP_8BIT) {
                if (ctx->bits_per_sample == 16) {
                    /* Truncate to 8-bit precision by zeroing the low byte */
                    uint8_t *p = pcm_buf + sample_idx * 2;
                    p[0] = 0;
                }
            }
            /* GROUP_16BIT and GROUP_NOOP: no change */

            sample_idx++;
        }
    }
    return sample_idx;
}


uint32_t adpcm_return_bytes(const AdpcmContext *ctx, int direction, uint32_t count)
{
    int method = (int)(int8_t)ctx->method_code;
    uint32_t bps = (uint32_t)ctx->bits_per_sample >> 3;

    /* G.726: passthrough */
    if (method >= ADPCM_METHOD_G726_2BIT && method <= ADPCM_METHOD_G726_5BIT)
        return count;

    if (method == ADPCM_METHOD_16BIT_PCM) {
        /* 16-bit PCM: always 2 bytes per sample */
        return (count / bps) * 2;
    }

    if (direction == ADPCM_DIRECTION_ENCODE) {
        /* Encode: PCM bytes → sample count (1 compressed byte per sample) */
        return count / bps;
    } else {
        /* Decode: sample count → PCM output bytes */
        return bps * count;
    }
}
