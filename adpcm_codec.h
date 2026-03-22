/*
 * adpcm_codec.h — Reconstructed ADPCM Codec (reverse engineered from DLL)
 *
 * A standalone reimplementation of a multi-method ADPCM audio codec.
 * Supports ADPCM2 (2/4/5/6/7/8-bit), ADPCM1 (4-bit), Non-linear PCM,
 * and linear PCM passthrough (8-bit and 16-bit).
 */

#ifndef ADPCM_CODEC_H
#define ADPCM_CODEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Codec Methods (external API indices)
 *
 * These are the indices passed to adpcm_reset().
 * Internally each maps to a different codec implementation.
 * ================================================================ */

enum {
    ADPCM_4BIT_ADPCM1      = 0,    /* 4:1 compression, 12-bit internal      */
    ADPCM_2BIT_ADPCM2      = 1,    /* 8:1 compression, 16-bit internal      */
    ADPCM_4BIT_ADPCM2      = 2,    /* 4:1 compression, 16-bit internal      */
    ADPCM_5BIT_ADPCM2      = 3,    /* 3.2:1 compression                     */
    ADPCM_6BIT_ADPCM2      = 4,    /* 2.7:1 compression                     */
    ADPCM_7BIT_ADPCM2      = 5,    /* 2.3:1 compression                     */
    ADPCM_8BIT_ADPCM2      = 6,    /* 2:1 compression                       */
    ADPCM_NONLINEAR_PCM    = 7,    /* 2:1, segmented companding             */
    ADPCM_8BIT_PCM         = 8,    /* 2:1, simple truncation                */
    ADPCM_16BIT_PCM        = 9,    /* 1:1, passthrough                      */
    ADPCM_NUM_METHODS      = 10,
};

/* Direction flags for adpcm_return_bytes() */
#define ADPCM_DIRECTION_ENCODE  1
#define ADPCM_DIRECTION_DECODE  0

/* ================================================================
 * Channel State
 * ================================================================ */

typedef struct {
    int32_t  predicted;     /* Current / predicted sample value          */
    int16_t  step_index;    /* Index into the step size table            */
    uint8_t  encoded_byte;  /* Last encoded/decoded code byte            */
    uint8_t  _pad;
    int32_t  accumulator;   /* Running reconstructed sample              */
} AdpcmChannelState;        /* 12 bytes, matches original DLL layout     */

/* ================================================================
 * Codec Context
 * ================================================================ */

#define ADPCM_MAX_CHANNELS  2

typedef struct {
    int       method;                                       /* External method index  */
    uint16_t  bits_per_sample;                              /* PCM format: 8 or 16   */
    uint16_t  num_channels;                                 /* 1 = mono, 2 = stereo  */
    AdpcmChannelState enc[ADPCM_MAX_CHANNELS];              /* Encoder channel state  */
    AdpcmChannelState dec[ADPCM_MAX_CHANNELS];              /* Decoder channel state  */
} AdpcmContext;

/* ================================================================
 * Public API
 * ================================================================ */

int         adpcm_get_num_methods(void);
const char *adpcm_get_method_name(int method);

void        adpcm_reset(AdpcmContext *ctx, int method,
                         uint16_t bits_per_sample, uint16_t num_channels);

uint32_t    adpcm_encode(AdpcmContext *ctx,
                          const uint8_t *pcm_in, uint8_t *out,
                          uint32_t pcm_byte_count);

uint32_t    adpcm_decode(AdpcmContext *ctx,
                          const uint8_t *in, uint8_t *pcm_out,
                          uint32_t sample_count);

uint32_t    adpcm_evaluate(AdpcmContext *ctx,
                            uint8_t *pcm_buf, uint32_t byte_count);

uint32_t    adpcm_return_bytes(const AdpcmContext *ctx,
                                int direction, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* ADPCM_CODEC_H */
