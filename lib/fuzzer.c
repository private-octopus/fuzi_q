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

uint32_t basic_packet_fuzzer(fuzzer_ctx_t* ctx, uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    int should_fuzz = 0;
    uint32_t fuzz_index = 0;

    /* Once in 16, fuzz by changing the length */
    if ((fuzz_pilot & 0xF) == 0xD) {
        uint32_t fuzz_length_max = (uint32_t)(length + 16u);
        uint32_t fuzzed_length;

        if (fuzz_length_max > bytes_max) {
            fuzz_length_max = (uint32_t)bytes_max;
        }
        fuzz_pilot >>= 4;
        fuzzed_length = 16 + (uint32_t)((fuzz_pilot & 0xFFFF) % fuzz_length_max);
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

    return (uint32_t)length;
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

static uint8_t test_frame_type_bad_reset_stream_offset[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1,
    1
};

static uint8_t test_type_bad_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};


static uint8_t test_type_bad_application_close[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_bad_max_stream_stream[] = {
    picoquic_frame_type_max_stream_data,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_bad_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_new_cid_length[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    0x3F,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_new_cid_retire[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    19,
    0x17
};

static uint8_t test_frame_type_bad_new_token[] = {
    picoquic_frame_type_new_token,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_bad_ack_range[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,
    5, 12
};

static uint8_t test_frame_type_bad_ack_gaps[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5, 12
};

static uint8_t test_frame_type_bad_ack_blocks[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_bad_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_datagram[] = {
    picoquic_frame_type_datagram_l,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_stream_hang[] = {
    0x01, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x01, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_path_abandon_bad_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x00, /* type 0 */
    /* 0x01, missing type */
    0x00, /* No error */
    0x00 /* No phrase */
};

static uint8_t test_frame_type_path_abandon_bad_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)),
    (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8),
    (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01, /* type 1 */
    0x01,
    0x11, /* Some new error */
    0x4f,
    0xff, /* bad length */
    (uint8_t)'b',
    (uint8_t)'a',
    (uint8_t)'d',
};

static uint8_t test_frame_type_path_abandon_bad_2[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x03, /* unknown type */
    0x00, /* No error */
    0x00 /* No phrase */
};


static uint8_t test_frame_type_bdp_bad[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04
};

static uint8_t test_frame_type_bdp_bad_addr[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04, 0x05, 1, 2, 3, 4, 5
};

static uint8_t test_frame_type_bdp_bad_length[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x08, 0x02, 0x04, 0x8F, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4
};

#define TEST_SKIP_ITEM(n, x) \
    {                        \
        n, x, sizeof(x),     \
    }

test_skip_frames_t test_skip_list[] = {
    TEST_SKIP_ITEM("padding", test_frame_type_padding),
    TEST_SKIP_ITEM("reset_stream", test_frame_type_reset_stream),
    TEST_SKIP_ITEM("connection_close", test_type_connection_close),
    TEST_SKIP_ITEM("application_close", test_type_application_close),
    TEST_SKIP_ITEM("application_close", test_type_application_close_reason),
    TEST_SKIP_ITEM("max_data", test_frame_type_max_data),
    TEST_SKIP_ITEM("max_stream_data", test_frame_type_max_stream_data),
    TEST_SKIP_ITEM("max_streams_bidir", test_frame_type_max_streams_bidir),
    TEST_SKIP_ITEM("max_streams_unidir", test_frame_type_max_streams_unidir),
    TEST_SKIP_ITEM("ping", test_frame_type_ping),
    TEST_SKIP_ITEM("blocked", test_frame_type_blocked),
    TEST_SKIP_ITEM("stream_data_blocked", test_frame_type_stream_blocked),
    TEST_SKIP_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir),
    TEST_SKIP_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir),
    TEST_SKIP_ITEM("new_connection_id", test_frame_type_new_connection_id),
    TEST_SKIP_ITEM("stop_sending", test_frame_type_stop_sending),
    TEST_SKIP_ITEM("challenge", test_frame_type_path_challenge),
    TEST_SKIP_ITEM("response", test_frame_type_path_response),
    TEST_SKIP_ITEM("new_token", test_frame_type_new_token),
    TEST_SKIP_ITEM("ack", test_frame_type_ack),
    TEST_SKIP_ITEM("ack_ecn", test_frame_type_ack_ecn),
    TEST_SKIP_ITEM("stream_min", test_frame_type_stream_range_min),
    TEST_SKIP_ITEM("stream_max", test_frame_type_stream_range_max),
    TEST_SKIP_ITEM("crypto_hs", test_frame_type_crypto_hs),
    TEST_SKIP_ITEM("retire_connection_id", test_frame_type_retire_connection_id),
    TEST_SKIP_ITEM("datagram", test_frame_type_datagram),
    TEST_SKIP_ITEM("datagram_l", test_frame_type_datagram_l),
    TEST_SKIP_ITEM("handshake_done", test_frame_type_handshake_done),
    TEST_SKIP_ITEM("ack_frequency", test_frame_type_ack_frequency),
    TEST_SKIP_ITEM("time_stamp", test_frame_type_time_stamp),
    TEST_SKIP_ITEM("path_abandon_0", test_frame_type_path_abandon_0),
    TEST_SKIP_ITEM("path_abandon_1", test_frame_type_path_abandon_1),
    TEST_SKIP_ITEM("path_abandon_2", test_frame_type_path_abandon_2),
    TEST_SKIP_ITEM("bdp", test_frame_type_bdp),
    TEST_SKIP_ITEM("bad_reset_stream_offset", test_frame_type_bad_reset_stream_offset),
    TEST_SKIP_ITEM("bad_reset_stream", test_frame_type_bad_reset_stream),
    TEST_SKIP_ITEM("bad_connection_close", test_type_bad_connection_close),
    TEST_SKIP_ITEM("bad_application_close", test_type_bad_application_close),
    TEST_SKIP_ITEM("bad_max_stream_stream", test_frame_type_bad_max_stream_stream),
    TEST_SKIP_ITEM("bad_max_streams_bidir", test_frame_type_max_bad_streams_bidir),
    TEST_SKIP_ITEM("bad_max_streams_unidir", test_frame_type_bad_max_streams_unidir),
    TEST_SKIP_ITEM("bad_new_connection_id_length", test_frame_type_bad_new_cid_length),
    TEST_SKIP_ITEM("bad_new_connection_id_retire", test_frame_type_bad_new_cid_retire),
    TEST_SKIP_ITEM("bad_stop_sending", test_frame_type_bad_stop_sending),
    TEST_SKIP_ITEM("bad_new_token", test_frame_type_bad_new_token),
    TEST_SKIP_ITEM("bad_ack_range", test_frame_type_bad_ack_range),
    TEST_SKIP_ITEM("bad_ack_gaps", test_frame_type_bad_ack_gaps),
    TEST_SKIP_ITEM("bad_ack_blocks", test_frame_type_bad_ack_blocks),
    TEST_SKIP_ITEM("bad_crypto_hs", test_frame_type_bad_crypto_hs),
    TEST_SKIP_ITEM("bad_datagram", test_frame_type_bad_datagram),
    TEST_SKIP_ITEM("stream_hang", test_frame_stream_hang),
    TEST_SKIP_ITEM("bad_abandon_0", test_frame_type_path_abandon_bad_0),
    TEST_SKIP_ITEM("bad_abandon_1", test_frame_type_path_abandon_bad_1),
    TEST_SKIP_ITEM("bad_abandon_2", test_frame_type_path_abandon_bad_2),
    TEST_SKIP_ITEM("bad_bdp", test_frame_type_bdp_bad),
    TEST_SKIP_ITEM("bad_bdp", test_frame_type_bdp_bad_addr),
    TEST_SKIP_ITEM("bad_bdp", test_frame_type_bdp_bad_length)
};

size_t nb_test_skip_list = sizeof(test_skip_list) / sizeof(test_skip_frames_t);

size_t length_non_padded(uint8_t* bytes, size_t length, size_t header_length)
{
    uint8_t* bytes_begin = bytes;
    uint8_t* bytes_last = bytes + length;
    uint8_t* final_pad = NULL;
    bytes += header_length;
    while (bytes != NULL && bytes < bytes_last) {
        if (*bytes == picoquic_frame_type_padding) {
            final_pad = bytes;
            do {
                bytes++;
            } while (bytes < bytes_last && *bytes == picoquic_frame_type_padding);
            if (bytes < bytes_last) {
                final_pad = NULL;
            }
        }
        else{
            size_t consumed = 0;
            int is_pure_ack = 0;

            if (picoquic_skip_frame(bytes, bytes_last - bytes, &consumed, &is_pure_ack) != 0) {
                bytes = NULL;
            }
            else {
                bytes += consumed;
            }
        }
    }

    return (final_pad == NULL) ? length : (final_pad - bytes_begin);
}

uint32_t initial_packet_fuzzer(fuzzer_ctx_t* ctx, uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    size_t len = test_skip_list[ctx->current_frame].len;
    int fuzzed = 0;
    size_t final_pad = length_non_padded(bytes, length, header_length);
    switch (ctx->fuzz_position) {
    case 0:
        if (final_pad + len <= bytes_max) {
            /* First test variant: add a random frame at the end of the packet */
            memcpy(&bytes[final_pad], test_skip_list[ctx->current_frame].val, len);
            if (len + final_pad > length) {
                length = len + final_pad;
            }
            fuzzed++;
        }
        break;
    case 1:
        if (final_pad + len <= bytes_max) {
            /* Second test variant: add a random frame at the beginning of the packet */
            memmove(bytes + header_length + len, bytes + header_length, final_pad);
            memcpy(&bytes[header_length], test_skip_list[ctx->current_frame].val, len);
            if (len + final_pad > length) {
                length = len + final_pad;
            }
            fuzzed++;
        }
        break;
    case 2:
        if (header_length + len <= bytes_max) {
            /* Third test variant: replace the packet by a random frame */
            memcpy(&bytes[header_length], test_skip_list[ctx->current_frame].val, len);
            fuzzed++;

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
    if (fuzzed) {
        ctx->nb_initial_fuzzed++;
        ctx->current_frame++;
    }
    return (uint32_t)length;
}

uint32_t basic_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    fuzzer_ctx_t* ctx = (fuzzer_ctx_t*)fuzz_ctx;
    uint64_t fuzz_pilot = picoquic_test_random(&ctx->random_context);
    int should_fuzz = 0;
    int should_fuzz_initial = 0;
    uint32_t fuzz_index = 0;
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);
    uint32_t fuzzed_length = (uint32_t)length;

    ctx->nb_packets++;
    
    if (cnx_state == picoquic_state_client_init_sent && !ctx->initial_fuzzing_done) {
        should_fuzz_initial = 1;
        if (ctx->current_frame >= nb_test_skip_list) {
            ctx->fuzz_position++;
            ctx->current_frame = 0;

            if (ctx->fuzz_position > 2) {
                ctx->fuzz_position = 0;
                ctx->initial_fuzzing_done = 1;
                should_fuzz_initial = 0;
            }
        }
    }
    else {
        DBG_PRINTF("%s", "test");
    }

    if (should_fuzz_initial) {
        fuzzed_length = initial_packet_fuzzer(ctx, fuzz_pilot, bytes, bytes_max, length, header_length);
    }
    else {
        if (cnx_state > ctx->highest_state_fuzzed) {
            should_fuzz = 1;
            ctx->highest_state_fuzzed = cnx_state;
        }
        else {
            /* if already fuzzed this state, fuzz one packet in 16 */
            should_fuzz = ((fuzz_pilot & 0xF) == 0xD);
        }
        fuzz_pilot >>= 4;
        if (should_fuzz) {
            fuzzed_length = basic_packet_fuzzer(ctx, fuzz_pilot, bytes, bytes_max, length, header_length);
        }
    }

    return (uint32_t)length;
}

void fuzzer_init(fuzzer_ctx_t* fuzz_ctx, uint64_t tweak)
{
    memset(fuzz_ctx, 0, sizeof(fuzzer_ctx_t));
    /* Random seed depends on duration, so different durations do not all start
     * with exactly the same message sequences. */
    fuzz_ctx->random_context = 0xDEADBEEFBABACAFEull;
    fuzz_ctx->random_context ^= tweak;
}