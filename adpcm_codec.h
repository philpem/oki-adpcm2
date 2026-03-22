/*
 * adpcm_codec.h — Reconstructed ADPCM Codec (reverse engineered from DLL)
 *
 * This is a standalone reimplementation of a multi-method ADPCM audio
 * compression/decompression library, reverse-engineered from x86 assembly
 * using Ghidra.
 *
 * Supports: ADPCM2 (2/4/5/6/7/8-bit), ADPCM1 (4-bit), Non-linear PCM,
 *           and linear PCM passthrough (8-bit and 16-bit).
 */

#ifndef ADPCM_CODEC_H
#define ADPCM_CODEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Method Codes
 * ================================================================ */

/* Internal method codes (0–13) */
#define ADPCM_METHOD_4BIT_ADPCM2       0
#define ADPCM_METHOD_5BIT_ADPCM2       1
#define ADPCM_METHOD_6BIT_ADPCM2       2
#define ADPCM_METHOD_7BIT_ADPCM2       3
#define ADPCM_METHOD_8BIT_ADPCM2       4
#define ADPCM_METHOD_4BIT_ADPCM1       5
#define ADPCM_METHOD_8BIT_PCM          6
#define ADPCM_METHOD_NONLINEAR_PCM     7
#define ADPCM_METHOD_16BIT_PCM         8
#define ADPCM_METHOD_G726_2BIT         9
#define ADPCM_METHOD_G726_3BIT        10
#define ADPCM_METHOD_G726_4BIT        11
#define ADPCM_METHOD_G726_5BIT        12
#define ADPCM_METHOD_2BIT_ADPCM2      13

#define ADPCM_NUM_INTERNAL_METHODS    14
#define ADPCM_NUM_EXTERNAL_METHODS    10

/* Encode/decode direction for adpcm_return_bytes() */
#define ADPCM_DIRECTION_ENCODE  1
#define ADPCM_DIRECTION_DECODE  0


/* ================================================================
 * Per-Channel State
 * ================================================================ */

typedef struct {
    int32_t  predicted;     /* Current / predicted sample value          */
    int16_t  step_index;    /* Index into the step size table            */
    uint8_t  encoded_byte;  /* Last encoded byte (output or input)       */
    uint8_t  _pad;
    int32_t  accumulator;   /* Running reconstructed sample              */
} AdpcmChannelState;        /* 12 bytes */


/* ================================================================
 * Codec Context
 * ================================================================ */

#define ADPCM_MAX_CHANNELS  2

typedef struct {
    uint8_t           _reserved[4];
    uint8_t           method_code;                          /* Internal code (0–13)    */
    uint8_t           _pad05;
    uint16_t          bits_per_sample;                      /* PCM format: 8 or 16     */
    uint16_t          num_channels;                         /* 1 = mono, 2 = stereo    */
    uint8_t           _pad0a[2];
    AdpcmChannelState enc_channels[ADPCM_MAX_CHANNELS];    /* Encoder state           */
    AdpcmChannelState dec_channels[ADPCM_MAX_CHANNELS];    /* Decoder state           */
} AdpcmContext;


/* ================================================================
 * Public API
 * ================================================================ */

/* Query available methods */
int         adpcm_get_num_methods(void);
const char *adpcm_get_method_name(int external_index);

/* Initialise / reset the codec context */
void        adpcm_reset(AdpcmContext *ctx, int external_method_index,
                         uint16_t bits_per_sample, uint16_t num_channels);

/* Encode PCM to compressed */
uint32_t    adpcm_encode(AdpcmContext *ctx,
                          const uint8_t *pcm_in, uint8_t *compressed_out,
                          uint32_t pcm_byte_count);

/* Decode compressed to PCM */
uint32_t    adpcm_decode(AdpcmContext *ctx,
                          const uint8_t *compressed_in, uint8_t *pcm_out,
                          uint32_t sample_count);

/* Trial encode + reconstruct in-place (for quality evaluation) */
uint32_t    adpcm_evaluate(AdpcmContext *ctx,
                            uint8_t *pcm_buf, uint32_t byte_count);

/* Calculate output byte count */
uint32_t    adpcm_return_bytes(const AdpcmContext *ctx,
                                int direction, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* ADPCM_CODEC_H */
