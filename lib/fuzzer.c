/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <picoquic.h>
#include <picoquic_internal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

/*
 * Basic fuzz test just tries to flip some bits in random packets
 */

uint32_t basic_fuzzer(void * fuzz_ctx, picoquic_cnx_t* cnx, 
    uint8_t * bytes, size_t bytes_max, size_t length, size_t header_length)
{
    basic_fuzzer_ctx_t * ctx = (basic_fuzzer_ctx_t *)fuzz_ctx;
    uint64_t fuzz_pilot = picoquic_test_random(&ctx->random_context);
    int should_fuzz = 0;
    uint32_t fuzz_index = 0;
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);

    ctx->nb_packets++;

    if (cnx_state > ctx->highest_state_fuzzed) {
        should_fuzz = 1;
        ctx->highest_state_fuzzed = cnx_state;
    } else {
        /* if already fuzzed this state, fuzz one packet in 16 */
        should_fuzz = ((fuzz_pilot & 0xF) == 0xD);
        fuzz_pilot >>= 4;
    }

    if (should_fuzz) {
        /* Once in 16, fuzz by changing the length */
        if ((fuzz_pilot & 0xF) == 0xD) {
            uint32_t fuzz_length_max = (uint32_t)(length + 16u);
            uint32_t fuzzed_length;

            if (fuzz_length_max > bytes_max) {
                fuzz_length_max = (uint32_t)bytes_max;
            }
            fuzz_pilot >>= 4;
            fuzzed_length = 16 + (uint32_t)((fuzz_pilot&0xFFFF) % fuzz_length_max);
            fuzz_pilot >>= 16;
            if (fuzzed_length > length) {
                for (uint32_t i = (uint32_t)length; i < fuzzed_length; i++) {
                    bytes[i] = (uint8_t)fuzz_pilot;
                }
            } 
            length = fuzzed_length;

            if (length < header_length) {
                length = header_length;
            }
            ctx->nb_fuzzed_length++;
        }
        /* Find the position that shall be fuzzed */
        fuzz_index = (uint32_t)((fuzz_pilot & 0xFFFF) % length);
        fuzz_pilot >>= 16;
        while (fuzz_pilot != 0 && fuzz_index < length) {
            /* flip one byte */
            bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
            fuzz_pilot >>= 8;
            ctx->nb_fuzzed++;
        }
    }

    return (uint32_t)length;
}

void basic_fuzzer_init(basic_fuzzer_ctx_t* fuzz_ctx, uint64_t tweak)
{
    memset(fuzz_ctx, 0, sizeof(basic_fuzzer_ctx_t));
    /* Random seed depends on duration, so different durations do not all start
     * with exactly the same message sequences. */
    fuzz_ctx->random_context = 0xDEADBEEFBABACAFEull;
    fuzz_ctx->random_context ^= tweak;
}

/*
 * Initial fuzz test.
 *
 * This test specializes in fuzzing the initial packet, and checking what happens. All the
 * packets sent there are illegitimate, and should result in broken connections.
 *
 * The test a set of test frames first defined for picoquic tests.
 */
typedef struct st_test_skip_frames_t {
    char const* name;
    uint8_t* val;
    size_t len;
    int is_pure_ack;
    int must_be_last;
    int epoch;
} test_skip_frames_t;

static uint8_t test_frame_type_padding[] = { 0, 0, 0 };

static uint8_t test_frame_type_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    1
};

static uint8_t test_type_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    9,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static uint8_t test_type_application_close[] = {
    picoquic_frame_type_application_close,
    0,
    0
};

static uint8_t test_type_application_close_reason[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    4,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_max_data[] = {
    picoquic_frame_type_max_data,
    0xC0, 0, 0x01, 0, 0, 0, 0, 0
};

static uint8_t test_frame_type_max_stream_data[] = {
    picoquic_frame_type_max_stream_data,
    1,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0x41, 0
};

static uint8_t test_frame_type_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0x41, 7
};

static uint8_t test_frame_type_ping[] = {
    picoquic_frame_type_ping
};

static uint8_t test_frame_type_blocked[] = {
    picoquic_frame_type_data_blocked,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_stream_blocked[] = {
    picoquic_frame_type_stream_data_blocked,
    0x80, 1, 0, 0,
    0x80, 0x02, 0, 0
};

static uint8_t test_frame_type_streams_blocked_bidir[] = {
    picoquic_frame_type_streams_blocked_bidir,
    0x41, 0
};

static uint8_t test_frame_type_streams_blocked_unidir[] = {
    picoquic_frame_type_streams_blocked_unidir,
    0x81, 2, 3, 4
};

static uint8_t test_frame_type_new_connection_id[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    17,
    0x17
};

static uint8_t test_frame_type_path_challenge[] = {
    picoquic_frame_type_path_challenge,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_path_response[] = {
    picoquic_frame_type_path_response,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_new_token[] = {
    picoquic_frame_type_new_token,
    17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_ack[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};
static uint8_t test_frame_type_ack_ecn[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_stream_range_min[] = {
    picoquic_frame_type_stream_range_min,
    1,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stream_range_max[] = {
    picoquic_frame_type_stream_range_min + 2 + 4,
    1,
    0x44, 0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_retire_connection_id[] = {
    picoquic_frame_type_retire_connection_id,
    1
};

static uint8_t test_frame_type_datagram[] = {
    picoquic_frame_type_datagram,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_datagram_l[] = {
    picoquic_frame_type_datagram_l,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_handshake_done[] = {
    picoquic_frame_type_handshake_done
};

static uint8_t test_frame_type_ack_frequency[] = {
    0x40, picoquic_frame_type_ack_frequency,
    17, 0x0A, 0x44, 0x20, 0x01
};

static uint8_t test_frame_type_time_stamp[] = {
    (uint8_t)(0x40 | (picoquic_frame_type_time_stamp >> 8)), (uint8_t)(picoquic_frame_type_time_stamp & 0xFF),
    0x44, 0
};

static uint8_t test_frame_type_path_abandon_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x00, /* type 0 */
    0x01,
    0x00, /* No error */
    0x00 /* No phrase */
};

static uint8_t test_frame_type_path_abandon_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01, /* type 1 */
    0x01,
    0x11, /* Some new error */
    0x03,
    (uint8_t)'b',
    (uint8_t)'a',
    (uint8_t)'d',
};

static uint8_t test_frame_type_path_abandon_2[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x02, /* type 2, this path */
    0x00, /* No error */
    0x00 /* No phrase */
};

static uint8_t test_frame_type_bdp[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x03,
    0x04, 0x0A, 0x0, 0x0, 0x01
};

#define TEST_SKIP_ITEM(n, x, a, l, e) \
    {                              \
        n, x, sizeof(x), a, l, e     \
    }

test_skip_frames_t test_skip_list[] = {
    TEST_SKIP_ITEM("padding", test_frame_type_padding, 1, 0, 0),
    TEST_SKIP_ITEM("reset_stream", test_frame_type_reset_stream, 0, 0, 3),
    TEST_SKIP_ITEM("connection_close", test_type_connection_close, 0, 0, 3),
    TEST_SKIP_ITEM("application_close", test_type_application_close, 0, 0, 3),
    TEST_SKIP_ITEM("application_close", test_type_application_close_reason, 0, 0, 3),
    TEST_SKIP_ITEM("max_data", test_frame_type_max_data, 0, 0, 3),
    TEST_SKIP_ITEM("max_stream_data", test_frame_type_max_stream_data, 0, 0, 3),
    TEST_SKIP_ITEM("max_streams_bidir", test_frame_type_max_streams_bidir, 0, 0, 3),
    TEST_SKIP_ITEM("max_streams_unidir", test_frame_type_max_streams_unidir, 0, 0, 3),
    TEST_SKIP_ITEM("ping", test_frame_type_ping, 0, 0, 3),
    TEST_SKIP_ITEM("blocked", test_frame_type_blocked, 0, 0, 3),
    TEST_SKIP_ITEM("stream_data_blocked", test_frame_type_stream_blocked, 0, 0, 3),
    TEST_SKIP_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir, 0, 0, 3),
    TEST_SKIP_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir, 0, 0, 3),
    TEST_SKIP_ITEM("new_connection_id", test_frame_type_new_connection_id, 0, 0, 3),
    TEST_SKIP_ITEM("stop_sending", test_frame_type_stop_sending, 0, 0, 3),
    TEST_SKIP_ITEM("challenge", test_frame_type_path_challenge, 1, 0, 3),
    TEST_SKIP_ITEM("response", test_frame_type_path_response, 1, 0, 3),
    TEST_SKIP_ITEM("new_token", test_frame_type_new_token, 0, 0, 3),
    TEST_SKIP_ITEM("ack", test_frame_type_ack, 1, 0, 3),
    TEST_SKIP_ITEM("ack_ecn", test_frame_type_ack_ecn, 1, 0, 3),
    TEST_SKIP_ITEM("stream_min", test_frame_type_stream_range_min, 0, 1, 3),
    TEST_SKIP_ITEM("stream_max", test_frame_type_stream_range_max, 0, 0, 3),
    TEST_SKIP_ITEM("crypto_hs", test_frame_type_crypto_hs, 0, 0, 2),
    TEST_SKIP_ITEM("retire_connection_id", test_frame_type_retire_connection_id, 0, 0, 3),
    TEST_SKIP_ITEM("datagram", test_frame_type_datagram, 0, 1, 3),
    TEST_SKIP_ITEM("datagram_l", test_frame_type_datagram_l, 0, 0, 3),
    TEST_SKIP_ITEM("handshake_done", test_frame_type_handshake_done, 0, 0, 3),
    TEST_SKIP_ITEM("ack_frequency", test_frame_type_ack_frequency, 0, 0, 3),
    TEST_SKIP_ITEM("time_stamp", test_frame_type_time_stamp, 1, 0, 3),
    TEST_SKIP_ITEM("path_abandon_0", test_frame_type_path_abandon_0, 0, 0, 3),
    TEST_SKIP_ITEM("path_abandon_1", test_frame_type_path_abandon_1, 0, 0, 3),
    TEST_SKIP_ITEM("path_abandon_2", test_frame_type_path_abandon_2, 0, 0, 3),
    TEST_SKIP_ITEM("bdp", test_frame_type_bdp, 0, 0, 3)
};

size_t nb_test_skip_list = sizeof(test_skip_list) / sizeof(test_skip_frames_t);

uint32_t initial_fuzzer(void * fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t * bytes, size_t bytes_max, size_t length, size_t header_length)
{
    initial_fuzzer_ctx_t * ctx = (initial_fuzzer_ctx_t *)fuzz_ctx;
    uint32_t should_fuzz = 0;
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);

    if (cnx_state == picoquic_state_client_init_sent) {
        should_fuzz = 1;
        if (ctx->initial_fuzzing_done == 0) {
            if (ctx->current_frame >= nb_test_skip_list) {
                ctx->fuzz_position++;
                ctx->current_frame = 0;

                if (ctx->fuzz_position > 2) {
                    ctx->fuzz_position = 0;
                    ctx->initial_fuzzing_done = 1;
                }
            }
        }
    }

    if (should_fuzz) {
        if (!ctx->initial_fuzzing_done) {
            size_t len = test_skip_list[ctx->current_frame].len;
            switch (ctx->fuzz_position) {
            case 0:
                if (length + len <= bytes_max) {
                    /* First test variant: add a random frame at the end of the packet */
                    memcpy(&bytes[length], test_skip_list[ctx->current_frame].val, len);
                    length += len;
                }
                break;
            case 1:
                if (length + len <= bytes_max) {
                    /* Second test variant: add a random frame at the beginning of the packet */
                    memmove(bytes + header_length + len, bytes + header_length, len);
                    memcpy(&bytes[header_length], test_skip_list[ctx->current_frame].val, len);
                    length += len;
                }
                break;
            case 2:
                if (length + len <= bytes_max) {
                    /* Third test variant: replace the packet by a random frame */
                    memcpy(&bytes[header_length], test_skip_list[ctx->current_frame].val, len);

                    if (length > header_length + len) {
                        /* If there is room left, */
                        memset(&bytes[header_length + len], 0, length - (header_length + len));
                    }
                    else {
                        length = header_length + len;
                    }
                }
                break;
            default:
                break;
            }
            ctx->current_frame++;
        }
        else {
            uint64_t fuzz_pilot = picoquic_test_random(&ctx->random_context);
            uint32_t fuzz_index = (uint32_t)((fuzz_pilot & 0xFFFF) % (uint32_t)length);
            uint8_t fuzz_length;
            fuzz_pilot >>= 16;
            fuzz_length = (uint8_t)(((fuzz_pilot & 0xFF) % 5) + 1);
            fuzz_pilot >>= 8;

            while (fuzz_length != 0 && fuzz_index < length) {
                /* flip one byte */
                bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
                fuzz_length--;
            }
        }
    }

    return (uint32_t)length;
}
