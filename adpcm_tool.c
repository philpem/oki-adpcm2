/*
 * adpcm_tool.c — Decode/encode ADPCM audio with WAV and SSA support
 *
 * Usage:
 *   adpcm_tool decode <input> <output.wav> [options]
 *   adpcm_tool encode <input.wav> <output> [options]
 *
 * Input formats for decode:
 *   .SSA   — Nibble-packed 4-bit ADPCM with 6-byte header (auto-detected)
 *   .bin   — Raw byte-per-sample ADPCM
 *
 * Output formats for encode:
 *   .SSA   — Nibble-packed with 6-byte header
 *   .bin   — Raw byte-per-sample
 *
 * Options:
 *   -m <index>    Method index 0–9 (default: 2 = 4bit ADPCM2)
 *   -r <rate>     Sample rate in Hz (default: 8000)
 *   -c <channels> Channel count 1 or 2 (default: 1)
 *   -b <bits>     PCM bits per sample, 8 or 16 (default: 16)
 *   -n            Force nibble-packed mode (auto for .SSA extension)
 *   -H <size>     Header size in bytes to skip on decode (default: 6 for SSA)
 *   -l            List available methods and exit
 *
 * Build:
 *   gcc -o adpcm_tool adpcm_tool.c adpcm_codec.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "adpcm_codec.h"

/* ----------------------------------------------------------------
 * WAV header
 * ---------------------------------------------------------------- */

#pragma pack(push, 1)
typedef struct {
    char     riff_id[4];
    uint32_t file_size;
    char     wave_id[4];
    char     fmt_id[4];
    uint32_t fmt_size;
    uint16_t audio_format;
    uint16_t num_channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;
    uint16_t bits_per_sample;
    char     data_id[4];
    uint32_t data_size;
} WavHeader;
#pragma pack(pop)

static void wav_header_init(WavHeader *h, uint16_t channels,
                            uint32_t sample_rate, uint16_t bits,
                            uint32_t data_bytes)
{
    memcpy(h->riff_id, "RIFF", 4);
    h->file_size = 36 + data_bytes;
    memcpy(h->wave_id, "WAVE", 4);
    memcpy(h->fmt_id, "fmt ", 4);
    h->fmt_size = 16;
    h->audio_format = 1;
    h->num_channels = channels;
    h->sample_rate = sample_rate;
    h->bits_per_sample = bits;
    h->block_align = channels * (bits / 8);
    h->byte_rate = sample_rate * h->block_align;
    memcpy(h->data_id, "data", 4);
    h->data_size = data_bytes;
}

/* ----------------------------------------------------------------
 * File I/O
 * ---------------------------------------------------------------- */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

/* Case-insensitive extension check */
static int has_extension(const char *path, const char *ext)
{
    size_t plen = strlen(path);
    size_t elen = strlen(ext);
    if (plen < elen) return 0;
    const char *tail = path + plen - elen;
    for (size_t i = 0; i < elen; i++) {
        char a = tail[i], b = ext[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

/* ----------------------------------------------------------------
 * Nibble pack / unpack
 *
 * SSA files store two 4-bit samples per byte, high nibble first.
 * The codec API uses one sample per byte (low 4 bits).
 * ---------------------------------------------------------------- */

static uint8_t *nibble_unpack(const uint8_t *packed, size_t packed_len,
                              size_t *out_len)
{
    *out_len = packed_len * 2;
    uint8_t *out = malloc(*out_len);
    if (!out) return NULL;
    for (size_t i = 0; i < packed_len; i++) {
        out[i * 2]     = packed[i] >> 4;
        out[i * 2 + 1] = packed[i] & 0x0F;
    }
    return out;
}

static uint8_t *nibble_pack(const uint8_t *samples, size_t sample_count,
                            size_t *out_len)
{
    *out_len = (sample_count + 1) / 2;
    uint8_t *out = calloc(*out_len, 1);
    if (!out) return NULL;
    for (size_t i = 0; i < sample_count; i++) {
        if (i % 2 == 0)
            out[i / 2] = (samples[i] & 0x0F) << 4;
        else
            out[i / 2] |= samples[i] & 0x0F;
    }
    return out;
}

/* ----------------------------------------------------------------
 * SSA header (6 bytes, partially understood)
 * ---------------------------------------------------------------- */

#define SSA_HEADER_SIZE 6

static const uint8_t SSA_HEADER_DEFAULT[SSA_HEADER_SIZE] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* ----------------------------------------------------------------
 * List methods
 * ---------------------------------------------------------------- */

static void list_methods(void)
{
    int n = adpcm_get_num_methods();
    printf("Available methods:\n");
    for (int i = 0; i < n; i++)
        printf("  %d: %s\n", i, adpcm_get_method_name(i));
}

/* ----------------------------------------------------------------
 * Decode
 * ---------------------------------------------------------------- */

static int do_decode(const char *in_path, const char *out_path,
                     int method, uint32_t sample_rate,
                     uint16_t channels, uint16_t bits,
                     int nibble_mode, int header_size)
{
    size_t in_size;
    uint8_t *in_data = read_file(in_path, &in_size);
    if (!in_data) return 1;

    if ((size_t)header_size >= in_size) {
        fprintf(stderr, "Header size (%d) >= file size (%zu)\n",
                header_size, in_size);
        free(in_data);
        return 1;
    }

    if (header_size > 0) {
        printf("Skipping %d-byte header:", header_size);
        for (int i = 0; i < header_size && i < 16; i++)
            printf(" %02x", in_data[i]);
        printf("\n");
    }

    uint8_t *compressed = in_data + header_size;
    size_t compressed_size = in_size - header_size;

    uint8_t *samples;
    uint32_t sample_count;

    if (nibble_mode) {
        size_t unpacked_len;
        samples = nibble_unpack(compressed, compressed_size, &unpacked_len);
        if (!samples) { free(in_data); return 1; }
        sample_count = (uint32_t)unpacked_len;
        printf("Unpacked %zu nibble-packed bytes -> %u samples\n",
               compressed_size, sample_count);
    } else {
        sample_count = (uint32_t)compressed_size;
        samples = malloc(sample_count);
        if (!samples) { free(in_data); return 1; }
        memcpy(samples, compressed, sample_count);
    }

    AdpcmContext ctx;
    adpcm_reset(&ctx, method, bits, channels);

    uint32_t pcm_bytes = adpcm_return_bytes(&ctx, ADPCM_DIRECTION_DECODE, sample_count);
    uint8_t *pcm = malloc(pcm_bytes);
    if (!pcm) { free(in_data); free(samples); return 1; }

    adpcm_decode(&ctx, samples, pcm, sample_count);

    WavHeader hdr;
    wav_header_init(&hdr, channels, sample_rate, bits, pcm_bytes);

    FILE *f = fopen(out_path, "wb");
    if (!f) { perror(out_path); free(in_data); free(samples); free(pcm); return 1; }
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(pcm, 1, pcm_bytes, f);
    fclose(f);

    double duration = (double)sample_count / channels / sample_rate;
    printf("Decoded %u samples -> %s (%.2fs, %u Hz, %u-bit, %u ch, %s)\n",
           sample_count, out_path, duration, sample_rate, bits, channels,
           adpcm_get_method_name(method));

    free(in_data);
    free(samples);
    free(pcm);
    return 0;
}

/* ----------------------------------------------------------------
 * Encode
 * ---------------------------------------------------------------- */

static int do_encode(const char *in_path, const char *out_path,
                     int method, uint16_t bits_override,
                     int nibble_mode, int write_header)
{
    size_t in_size;
    uint8_t *in_data = read_file(in_path, &in_size);
    if (!in_data) return 1;

    if (in_size < sizeof(WavHeader)) {
        fprintf(stderr, "File too small to be a WAV\n");
        free(in_data);
        return 1;
    }

    WavHeader *hdr = (WavHeader *)in_data;
    if (memcmp(hdr->riff_id, "RIFF", 4) != 0 ||
        memcmp(hdr->wave_id, "WAVE", 4) != 0) {
        fprintf(stderr, "Not a valid WAV file\n");
        free(in_data);
        return 1;
    }
    if (hdr->audio_format != 1) {
        fprintf(stderr, "Only uncompressed PCM WAV is supported\n");
        free(in_data);
        return 1;
    }

    uint16_t channels = hdr->num_channels;
    uint16_t bits = bits_override ? bits_override : hdr->bits_per_sample;
    uint32_t pcm_bytes = hdr->data_size;
    uint8_t *pcm = in_data + sizeof(WavHeader);

    AdpcmContext ctx;
    adpcm_reset(&ctx, method, bits, channels);

    uint32_t out_samples = adpcm_return_bytes(&ctx, ADPCM_DIRECTION_ENCODE, pcm_bytes);

    uint8_t *compressed = malloc(out_samples);
    if (!compressed) { free(in_data); return 1; }

    adpcm_encode(&ctx, pcm, compressed, pcm_bytes);

    FILE *f = fopen(out_path, "wb");
    if (!f) { perror(out_path); free(in_data); free(compressed); return 1; }

    if (nibble_mode) {
        if (write_header)
            fwrite(SSA_HEADER_DEFAULT, 1, SSA_HEADER_SIZE, f);

        size_t packed_len;
        uint8_t *packed = nibble_pack(compressed, out_samples, &packed_len);
        if (!packed) {
            fclose(f); free(in_data); free(compressed);
            return 1;
        }
        fwrite(packed, 1, packed_len, f);
        fclose(f);

        uint32_t total = (write_header ? SSA_HEADER_SIZE : 0) + (uint32_t)packed_len;
        printf("Encoded %s -> %u bytes%s (%s, %u Hz, %u ch, nibble-packed)\n",
               in_path, total, write_header ? " (with SSA header)" : "",
               adpcm_get_method_name(method), hdr->sample_rate, channels);
        free(packed);
    } else {
        fwrite(compressed, 1, out_samples, f);
        fclose(f);
        printf("Encoded %s -> %u bytes (%s, %u Hz, %u ch)\n",
               in_path, out_samples, adpcm_get_method_name(method),
               hdr->sample_rate, channels);
    }

    free(in_data);
    free(compressed);
    return 0;
}

/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s decode <input> <output.wav> [options]\n"
        "  %s encode <input.wav> <output> [options]\n"
        "  %s -l\n"
        "\n"
        "Nibble-packed .SSA format is auto-detected by file extension.\n"
        "\n"
        "Options:\n"
        "  -m <index>     Method index 0-9 (default: 2 = 4bit ADPCM2)\n"
        "  -r <rate>      Sample rate in Hz (default: 8000)\n"
        "  -c <channels>  Channels, 1 or 2 (default: 1)\n"
        "  -b <bits>      PCM bits, 8 or 16 (default: 16)\n"
        "  -n             Force nibble-packed mode\n"
        "  -H <size>      Header bytes to skip/write (default: 6 for SSA, 0 otherwise)\n"
        "  -l             List methods\n",
        prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 1; }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0) {
            list_methods();
            return 0;
        }
    }

    if (argc < 4) { usage(argv[0]); return 1; }

    const char *cmd = argv[1];
    const char *in_path = argv[2];
    const char *out_path = argv[3];

    int method = 2;
    uint32_t sample_rate = 8000;
    uint16_t channels = 1;
    uint16_t bits = 16;
    int nibble_mode = -1;
    int header_size = -1;

    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
            method = atoi(argv[++i]);
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
            sample_rate = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
            channels = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
            bits = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-n") == 0)
            nibble_mode = 1;
        else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc)
            header_size = atoi(argv[++i]);
    }

    if (method < 0 || method >= adpcm_get_num_methods()) {
        fprintf(stderr, "Invalid method %d (use -l to list)\n", method);
        return 1;
    }

    /* Auto-detect nibble mode from file extension */
    if (nibble_mode < 0) {
        if (strcmp(cmd, "decode") == 0)
            nibble_mode = has_extension(in_path, ".ssa");
        else
            nibble_mode = has_extension(out_path, ".ssa");
    }

    if (header_size < 0)
        header_size = nibble_mode ? SSA_HEADER_SIZE : 0;

    if (strcmp(cmd, "decode") == 0) {
        return do_decode(in_path, out_path, method, sample_rate,
                         channels, bits, nibble_mode, header_size);
    } else if (strcmp(cmd, "encode") == 0) {
        return do_encode(in_path, out_path, method, bits,
                         nibble_mode, nibble_mode && header_size > 0);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
