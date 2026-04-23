/*
 * nsigii_audio_lte.c — NSIGII LTE Audio WAV Verifier
 * OBINexus SDK | MMUKO OS Design and Technology LLC
 * Author: Nnamdi Michael Okpala
 *
 * STDOUT = raw PCM samples  (pipe to ffplay/sox/aplay)
 * STDERR = verification log (human readable)
 *
 * Usage:
 *   Windows (ffplay):
 *     ./nsigii_audio_lte obiwords.wav | ffplay -f s16le -ar 44100 -i pipe:0 -ac 2
 *   Linux:
 *     ./nsigii_audio_lte file.wav | aplay -r 44100 -c 2 -f S16_LE
 *   Mac:
 *     ./nsigii_audio_lte file.wav | sox -t raw -r 44100 -c 2 -e signed -b 16 - -d
 */

#include "nsigii_lte.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define CHUNK_BYTES  4096
#define MAX_CHUNKS   2048

typedef enum {
    ODTS_STOPPED  = 0,
    ODTS_PLAYING  = 1,
    ODTS_PAUSED   = 2,
    ODTS_REJECTED = 3
} ODTSState;

typedef struct __attribute__((packed)) {
    char     riff[4];
    uint32_t file_size;
    char     wave[4];
    char     fmt[4];
    uint32_t fmt_size;
    uint16_t audio_format;
    uint16_t num_channels;
    uint32_t sample_rate;
    uint32_t byte_rate;
    uint16_t block_align;
    uint16_t bits_per_sample;
    char     data[4];
    uint32_t data_size;
} WAVHeader;

typedef struct {
    FILE      *file;
    WAVHeader  header;
    size_t     data_offset;
    size_t     total_chunks;
    size_t     current_chunk;
    LTEChain   chain;
    uint8_t    chunk_buf[CHUNK_BYTES];
    size_t     chunk_sizes[MAX_CHUNKS];
    ODTSState  state;
    double     playback_speed;
    size_t     frames_verified;
    size_t     frames_played;
    size_t     tamper_count;
} NSIGIIPlayer;

static volatile int g_pause_requested = 0;
static volatile int g_quit_requested  = 0;

static void on_signal(int sig) {
    if (sig == SIGINT)  g_pause_requested = 1;
    if (sig == SIGTERM) g_quit_requested  = 1;
}

/* ─── WAV open ────────────────────────────────────────────────────────────── */

static int wav_open(NSIGIIPlayer *p, const char *path) {
    p->file = fopen(path, "rb");
    if (!p->file) { fprintf(stderr, "[LTE] Cannot open: %s\n", path); return -1; }

    if (fread(&p->header, sizeof(WAVHeader), 1, p->file) != 1) {
        fprintf(stderr, "[LTE] Cannot read WAV header\n"); return -1;
    }
    if (memcmp(p->header.riff, "RIFF", 4) != 0 ||
        memcmp(p->header.wave, "WAVE", 4) != 0) {
        fprintf(stderr, "[LTE] Not a valid WAV file\n"); return -1;
    }

    p->data_offset  = sizeof(WAVHeader);
    p->total_chunks = (p->header.data_size + CHUNK_BYTES - 1) / CHUNK_BYTES;
    if (p->total_chunks > MAX_CHUNKS) p->total_chunks = MAX_CHUNKS;

    fprintf(stderr, "[LTE] WAV opened: %s\n", path);
    fprintf(stderr, "      Channels    : %u\n",    p->header.num_channels);
    fprintf(stderr, "      Sample rate : %u Hz\n", p->header.sample_rate);
    fprintf(stderr, "      Bits/sample : %u\n",    p->header.bits_per_sample);
    fprintf(stderr, "      Data size   : %u bytes\n", p->header.data_size);
    fprintf(stderr, "      Chunks      : %zu x %d bytes\n",
            p->total_chunks, CHUNK_BYTES);
    fprintf(stderr, "\n[LTE] Pipe this to your speaker:\n");
    fprintf(stderr, "  ffplay: ./nsigii_audio_lte %s"
            " | ffplay -f s16le -ar %u -ch_layout %s -i pipe:0\n",
            path, p->header.sample_rate,
            p->header.num_channels == 2 ? "stereo" : "mono");
    fprintf(stderr, "  aplay:  ./nsigii_audio_lte %s"
            " | aplay -r %u -c %u -f S16_LE\n\n",
            path, p->header.sample_rate, p->header.num_channels);
    return 0;
}

/* ─── Phase 1: LINK ───────────────────────────────────────────────────────── */

static int lte_link_all_chunks(NSIGIIPlayer *p) {
    fprintf(stderr, "[LTE LINK] Hashing %zu chunks...\n", p->total_chunks);
    fseek(p->file, (long)p->data_offset, SEEK_SET);

    uint8_t prev[LTE_HASH_SIZE];
    memset(prev, 0, LTE_HASH_SIZE);

    for (size_t i = 0; i < p->total_chunks; i++) {
        size_t n = fread(p->chunk_buf, 1, CHUNK_BYTES, p->file);
        if (n == 0) break;
        p->chunk_sizes[i] = n;

        LTEArtifact artifact;
        memset(&artifact, 0, sizeof(artifact));

        char name[LTE_NAME_SIZE];
        snprintf(name, sizeof(name), "audio_chunk_%04zu", i);

        LTEResult r = lte_link(&artifact, name, p->chunk_buf, n, prev);
        if (r != LTE_OK) {
            fprintf(stderr, "[LTE LINK] Failed chunk %zu: %s\n",
                    i, lte_result_label(r));
            return -1;
        }
        memcpy(prev, artifact.link_hash, LTE_HASH_SIZE);

        r = lte_chain_append(&p->chain, &artifact);
        if (r != LTE_OK) {
            fprintf(stderr, "[LTE LINK] Chain append failed chunk %zu: %s\n",
                    i, lte_result_label(r));
            return -1;
        }

        if (i % 100 == 0 || i == p->total_chunks - 1)
            fprintf(stderr, "  linked %zu/%zu  hash:%.16s...\n",
                    i + 1, p->total_chunks,
                    p->chain.artifacts[i].link_hex);
    }

    fprintf(stderr, "[LTE LINK] COMPLETE — %zu artifacts\n\n", p->chain.count);
    return 0;
}

/* ─── Phase 2: EXECUTE — verify each chunk, write PCM to stdout ───────────── */

static int lte_play(NSIGIIPlayer *p) {
    fprintf(stderr,
            "[LTE EXECUTE] Streaming verified PCM → stdout\n"
            "              Ctrl+C = PAUSE  |  Ctrl+C again = RESUME\n\n");

    p->state          = ODTS_PLAYING;
    p->playback_speed = 1.0;
    p->current_chunk  = 0;

    fseek(p->file, (long)p->data_offset, SEEK_SET);

    while (p->current_chunk < p->chain.count && !g_quit_requested) {

        /* PAUSE/RESUME */
        if (g_pause_requested) {
            g_pause_requested = 0;
            if (p->state == ODTS_PLAYING) {
                p->state = ODTS_PAUSED;
                fprintf(stderr,
                        "\n[STOP] Paused at chunk %zu/%zu"
                        " — Ctrl+C to resume.\n",
                        p->current_chunk, p->chain.count);
                while (p->state == ODTS_PAUSED
                       && !g_pause_requested && !g_quit_requested) {
                    struct timespec ts = {0, 50000000};
                    nanosleep(&ts, NULL);
                }
                if (g_pause_requested) {
                    g_pause_requested = 0;
                    p->state = ODTS_PLAYING;
                    fprintf(stderr, "[RELAY] Resuming from chunk %zu\n\n",
                            p->current_chunk);
                }
                continue;
            }
        }

        /* read chunk from file */
        size_t n = fread(p->chunk_buf, 1, CHUNK_BYTES, p->file);
        if (n == 0) break;

        /* real-time LTE verify before output */
        const LTEArtifact *a = &p->chain.artifacts[p->current_chunk];
        LTEResult vr = lte_verify(a, p->chunk_buf, n);

        fprintf(stderr, "[RELAY  ] chunk %04zu/%04zu  %s  hash:%.12s...",
                p->current_chunk + 1, p->chain.count,
                vr == LTE_OK ? "VERIFIED " : "TAMPERED!",
                a->link_hex);

        if (vr != LTE_OK) {
            p->tamper_count++;
            p->state = ODTS_REJECTED;
            fprintf(stderr, "  [HALT — chain broken]\n");
            break;
        }

        p->frames_verified++;
        p->frames_played++;

        /*
         * EXECUTE: chunk is constitutionally verified.
         * Write raw PCM to stdout — receiver plays it.
         * Stdout is binary; stderr carries the log.
         */
        fwrite(p->chunk_buf, 1, n, stdout);
        fflush(stdout);

        double ms = ((double)n / (double)p->header.byte_rate) * 1000.0;
        fprintf(stderr, "  [%.0fms]\n", ms);

        p->current_chunk++;
    }

    return 0;
}

/* ─── Synthetic WAV ───────────────────────────────────────────────────────── */

static const char *make_test_wav(void) {
    const char *path = "/tmp/nsigii_test.wav";
    FILE *f = fopen(path, "wb");
    if (!f) return NULL;

    uint32_t ns = 44100 * 2;
    uint32_t ds = ns * 2;
    WAVHeader h; memset(&h, 0, sizeof(h));
    memcpy(h.riff,"RIFF",4); h.file_size=36+ds;
    memcpy(h.wave,"WAVE",4); memcpy(h.fmt,"fmt ",4);
    h.fmt_size=16; h.audio_format=1; h.num_channels=1;
    h.sample_rate=44100; h.bits_per_sample=16;
    h.byte_rate=88200; h.block_align=2;
    memcpy(h.data,"data",4); h.data_size=ds;
    fwrite(&h, sizeof(h), 1, f);

    for (uint32_t i = 0; i < ns; i++) {
        double t = (double)i / 44100.0;
        double v = 16000.0 * (t * 440.0 * 6.28318530 -
                   (int)(t * 440.0 * 6.28318530) - 0.5);
        int16_t s = (int16_t)v;
        fwrite(&s, 2, 1, f);
    }
    fclose(f);
    return path;
}

/* ─── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    fprintf(stderr, "NSIGII LTE Audio Verifier\n");
    fprintf(stderr, "OBINexus SDK | MMUKO OS | Linkable Then Executable\n");
    fprintf(stderr, "====================================================\n\n");

    const char *wav_path = (argc >= 2) ? argv[1] : NULL;

    if (!wav_path) {
        fprintf(stderr, "[INFO] No file given — generating test tone.\n");
        fprintf(stderr, "Usage: %s <file.wav>"
                " | ffplay -f s16le -ar 44100 -ac 1 -i pipe:0\n\n", argv[0]);
        wav_path = make_test_wav();
        if (!wav_path) { fprintf(stderr, "[LTE] Cannot create test WAV\n"); return 1; }
    }

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    NSIGIIPlayer player;
    memset(&player, 0, sizeof(player));

    if (wav_open(&player, wav_path) != 0) return 1;
    if (lte_link_all_chunks(&player) != 0) {
        fprintf(stderr, "[LTE] Link failed. Cannot execute.\n");
        fclose(player.file); return 1;
    }

    lte_play(&player);

    fprintf(stderr, "\n====================================================\n");
    fprintf(stderr, "NSIGII LTE Report\n");
    fprintf(stderr, "  State    : %s\n",
            player.state == ODTS_REJECTED   ? "REJECTED" :
            player.current_chunk >= player.chain.count ? "COMPLETE" : "STOPPED");
    fprintf(stderr, "  Linked   : %zu\n", player.chain.count);
    fprintf(stderr, "  Verified : %zu\n", player.frames_verified);
    fprintf(stderr, "  Played   : %zu\n", player.frames_played);
    fprintf(stderr, "  Tampered : %zu\n", player.tamper_count);
    fprintf(stderr, "  Consensus: %s\n",
            player.tamper_count == 0 ? "OK — chain intact" : "BROKEN");

    fclose(player.file);
    return player.tamper_count == 0 ? 0 : 1;
}
