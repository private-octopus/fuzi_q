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
#include <picoquic_utils.h>
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
    uint32_t fuzz_index = 0;

    /* Once in 64, fuzz by changing the length */
    if ((fuzz_pilot & 0x3F) == 0xD) {
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
    else {
        size_t fuzz_target = length - header_length;
        if (fuzz_target > 0) {
            /* Find the position that shall be fuzzed */
            fuzz_index = (uint32_t)(header_length + (fuzz_pilot & 0xFFFF) % fuzz_target);
            fuzz_pilot >>= 16;
            while (fuzz_pilot != 0 && fuzz_index < length) {
                /* flip one byte */
                bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
                ctx->nb_fuzzed++;
            }
        }
    }

    return (uint32_t)length;
}

/* Frame specific fuzzers.
 * Most frames contain a series of fields, with different fuzzing priorities:
 * - The frame type should generally not be fuzzed, except for the rare cases when
 *   it includes variables, e.g., stream data frames with Fin, Length and Offset bits.
 * - Some frames contain data fields, such as content of data frames, or reason
 *   phrase for connection close. Changing that content should be a very low
 *   priority.
 * - Some fields express lengths of content, e.g., length of data or length of
 *   a reason phrase. There are interesting values that can be tried, such as
 *   zero, larger than packet length, exactly 1 byte larger than packet length,
 *   and of course any random value -- see varints.
 * - When fields include stream identifiers, interesting values include streams
 *   that are not open yet, streams that are open and different from current,
 *   old streams that are now closed, and of course random values.
 * - When fields are expressed as varint, it might be interesting to try
 *   specific values like FFFFFFFF, FFFF, FFFFFFFFFFFFFFFF, etc. And of course
 *   any random value.
 * A fraction of fuzzing attempts should avoid being smart: just flip random
 * bytes somewhere in the frame. As the number of fuzzing attempts increase,
 * it may be a good idea to increase that fraction.
 */

void fuzz_random_byte(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    if (bytes != NULL) {
        size_t l = bytes_max - bytes;
        size_t x = fuzz_pilot % l;
        uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 8);
        bytes[x] ^= byte_mask;
    }
}

uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz)
{
    if (bytes != NULL) {
        uint8_t* head_bytes = bytes;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
        if (bytes != NULL && do_fuzz){
            size_t l = bytes - head_bytes;
            size_t x = fuzz_pilot % l;
            uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 3);
            if (x == 0) {
                byte_mask &= 0x3f;
            }
            bytes[x] ^= byte_mask;
        }
    }
    return bytes;
}

/* ACK frame fuzzer.
 * ACK frame is composed of a series of varints. Default fuzz picks one of these varints
 * at random and flips it.
 */
void ack_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    /* Assume that we have short integers, one per byte */
    size_t fuzz_target;
    size_t nb_skipped = 0;
    uint8_t * first_byte = bytes;
    /* Count the varints in the list */
    while (bytes != NULL && bytes < bytes_max) {
        nb_skipped++;
        bytes = (uint8_t*)picoquic_frames_varint_skip(bytes, bytes_max);
    }
    /* Pick one at random */
    if (nb_skipped <= 1) {
        fuzz_target = 0;
    }
    else {
        fuzz_target = 1 + fuzz_pilot % (nb_skipped - 1);
    }
    fuzz_pilot >>= 8;
    /* Skip all the varints before the selected one */
    bytes = first_byte;
    nb_skipped = 0;

    while (bytes != NULL && bytes < bytes_max && nb_skipped < fuzz_target) {
        nb_skipped++;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
    }
    /* Fuzz the selected varint */
    fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, 1);
}

/* Stream frame fuzzer. 
 * Variations:
 *    -- flip a FIN bit
 *    -- fuzz length
 *    -- fuzz stream ID
 *    -- fuzz illegal offset
 * The fuzzing depends on how much space is available. It is always possible to
 * fuzz "in place", rewriting a var int by a var int of the same length, but if
 * there is space behind the frame it is also possible to extend the length of the
 * fields.
 */

void stream_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    int was_fuzzed = 0;
    uint8_t* first_byte = bytes;
    /* From the type octet, get the various bits that could be flipped */
    int len = bytes[0] & 2;
    int off = bytes[0] & 4;
    int fuzz_id = 0;
    int fuzz_length = 0;
    int fuzz_offset = 0;
    int fuzz_stream_id = 0;
    int fuzz_random = 0;

    /* From the random field, select a framing variant.
     * If selected field is omitted, fuzz the header instead.
     */
    uint64_t fuzz_variant = (fuzz_pilot ^ 0x57ea3f8a3ef822e8ull) % 5;

    switch (fuzz_variant) {
    case 0:
        bytes[0] ^= 1;
        break;
    case 1:
        if (len) {
            /* fuzz the length */
            fuzz_length = 1;
        }
        else {
            bytes[0] ^= 2;
        }
        break;
    case 2:
        if (off) {
            /* fuzz offset */
            fuzz_offset = 1;
        }
        else {
            bytes[0] ^= 4;
        }
        break;
    case 3:
        /* fuzz stream ID */
        fuzz_stream_id = 1;
        break;
    default:
        /* fuzz random byte */
        break;
    }

    if (bytes < bytes_max) {
        bytes++;
    }
    else {
        bytes = NULL;
    }

    bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, fuzz_stream_id);

    if (off) {
        bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, fuzz_offset);
    }

    /* TODO: may want to be a bit smarter when fuzzing the length */
    if (len) {
        bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, fuzz_length);
    }

    if (bytes != NULL && fuzz_random) {
        fuzz_random_byte(fuzz_pilot, first_byte + 1, bytes_max);
    }
}

/* Default frame fuzzer. Skip the frame type, then flip at random one of the first 8 bytes */
void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* frame_byte = bytes;

    bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);

    if (bytes == NULL || bytes >= bytes_max) {
        bytes = frame_byte;
    }
    if (bytes + 8 < bytes_max) {
        bytes_max = bytes + 8;
    }
    fuzz_random_byte(fuzz_pilot, bytes, bytes_max); 
}

#define FUZZER_MAX_NB_FRAMES 32

int frame_header_fuzzer(uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    uint8_t* frame_head[FUZZER_MAX_NB_FRAMES];
    uint8_t* frame_next[FUZZER_MAX_NB_FRAMES];
    uint8_t* last_byte = bytes + bytes_max;
    size_t nb_frames = 0;
    int was_fuzzed = 1;

    bytes += header_length;

    while (bytes != NULL && bytes < last_byte && nb_frames < FUZZER_MAX_NB_FRAMES) {
        size_t consumed = 0;
        int is_pure_ack = 1;
        frame_head[nb_frames] = bytes;
        if (picoquic_skip_frame(bytes, last_byte - bytes, &consumed, &is_pure_ack) == 0) {
            bytes += consumed;
            frame_next[nb_frames] = bytes;
            nb_frames++;
        }
        else {
            frame_next[nb_frames] = last_byte;
            bytes = NULL;
        }
    }

    if (nb_frames > 0) {
        size_t fuzzed_frame = (size_t)(fuzz_pilot % nb_frames);
        uint8_t* frame_byte = frame_head[fuzzed_frame];
        uint8_t* frame_max = frame_next[fuzzed_frame];

        fuzz_pilot >>= 5;

        if (PICOQUIC_IN_RANGE(*frame_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            stream_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
        }
        else {
            switch (*frame_byte) {
            case picoquic_frame_type_ack:
            case picoquic_frame_type_ack_ecn:
                ack_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_padding:
            case picoquic_frame_type_reset_stream:
            case picoquic_frame_type_connection_close:
            case picoquic_frame_type_application_close:
            case picoquic_frame_type_max_data:
            case picoquic_frame_type_max_stream_data:
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
            case picoquic_frame_type_ping:
            case picoquic_frame_type_data_blocked:
            case picoquic_frame_type_stream_data_blocked:
            case picoquic_frame_type_streams_blocked_bidir:
            case picoquic_frame_type_streams_blocked_unidir:
            case picoquic_frame_type_new_connection_id:
            case picoquic_frame_type_stop_sending:
            case picoquic_frame_type_path_challenge:
            case picoquic_frame_type_path_response:
            case picoquic_frame_type_crypto_hs:
            case picoquic_frame_type_new_token:
            case picoquic_frame_type_retire_connection_id:
            case picoquic_frame_type_handshake_done:
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                default_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            default: {
                uint64_t frame_id64;
                if (picoquic_frames_varint_decode(frame_byte, frame_max, &frame_id64) != NULL) {
                    switch (frame_id64) {
                    case picoquic_frame_type_ack_mp:
                    case picoquic_frame_type_ack_mp_ecn:
                        ack_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    case picoquic_frame_type_ack_frequency:
                    case picoquic_frame_type_time_stamp:
                    case picoquic_frame_type_path_abandon:
                    case picoquic_frame_type_bdp:
                    default:
                        default_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    }
                }
                break;
            }
            }
        }
    }

    return was_fuzzed;
}

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

fuzzer_cnx_state_enum fuzzer_get_cnx_state(picoquic_cnx_t* cnx)
{
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);
    fuzzer_cnx_state_enum fuzz_cnx_state = fuzzer_cnx_state_initial;

    if (cnx_state == picoquic_state_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_ready;
    }
    else if (cnx_state > picoquic_state_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }
    else if (cnx_state >= picoquic_state_client_almost_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_not_ready;
    }
    return fuzz_cnx_state;
}

uint32_t fuzi_q_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    /* Get the global fuzzing context */
    fuzzer_ctx_t* ctx = (fuzzer_ctx_t*)fuzz_ctx;
    /* Get the fuzzing context for this CID */
    uint64_t current_time = picoquic_get_quic_time(cnx->quic);
    fuzzer_icid_ctx_t* icid_ctx = fuzzer_get_icid_ctx(ctx, &cnx->initial_cnxid, current_time);
    uint64_t fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
    fuzzer_cnx_state_enum fuzz_cnx_state = fuzzer_get_cnx_state(cnx);
    uint32_t fuzzed_length = (uint32_t)length;
    int fuzz_again = ((fuzz_pilot & 0xf) <= 7);

    if (fuzz_cnx_state < 0 || fuzz_cnx_state >= fuzzer_cnx_state_max) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }

    fuzz_pilot >>= 4;

    if (icid_ctx != NULL && icid_ctx->target_state < fuzzer_cnx_state_max && icid_ctx->target_state >= 0) {
        ctx->nb_packets++;
        ctx->nb_packets_state[fuzz_cnx_state] += 1;
        icid_ctx->wait_count[fuzz_cnx_state]++;
        /* Compute the max number of packets that could be waited for.
         */
        if (!icid_ctx->already_fuzzed && fuzz_cnx_state != fuzzer_cnx_state_closing &&
            icid_ctx->wait_count[fuzz_cnx_state] > ctx->wait_max[fuzz_cnx_state]) {
            ctx->wait_max[fuzz_cnx_state] = icid_ctx->wait_count[fuzz_cnx_state];
        }
        /* Only perform fuzzing if the connection has reached or passed the target state. */
        if ((fuzz_cnx_state > icid_ctx->target_state ||
            (fuzz_cnx_state == icid_ctx->target_state &&
                icid_ctx->wait_count[fuzz_cnx_state] >= icid_ctx->target_wait)) &&
            (!icid_ctx->already_fuzzed || fuzz_again)) {
            /* Based on the fuzz pilot, pick one of the following */
            uint64_t next_step = fuzz_pilot & 0x03;
            size_t final_pad = length_non_padded(bytes, length, header_length);
            size_t fuzz_frame_id = (size_t)((fuzz_pilot >> 3) % nb_fuzi_q_frame_list);
            size_t len = fuzi_q_frame_list[fuzz_frame_id].len;
            int fuzz_more = ((fuzz_pilot >> 8) & 1) > 0;
            int was_fuzzed = 0;
            fuzz_pilot >>= 9;

            switch (next_step) {
            case 0:
                if (final_pad + len <= bytes_max) {
                    /* First test variant: add a random frame at the end of the packet */
                    memcpy(&bytes[final_pad], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    final_pad += len;
                    was_fuzzed++;
                }
                break;
            case 1:
                if (final_pad + len <= bytes_max) {
                    /* Second test variant: add a random frame at the beginning of the packet */
                    memmove(bytes + header_length + len, bytes + header_length, final_pad);
                    memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    final_pad += len;
                    was_fuzzed++;
                }
                break;
            case 2:
                if (header_length + len <= bytes_max) {
                    /* Third test variant: replace the packet by a random frame */
                    memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    was_fuzzed++;
                    final_pad = header_length + len;
                }
                break;
            default:
                len = 0;
                break;
            }
            /* TODO: based on the fuzz pilot, consider padding multiple frames */

            if (final_pad > length) {
                fuzzed_length = (uint32_t)final_pad;
            }
            else {
                /* If there is room left, pad. */
                memset(&bytes[header_length + len], 0, length - (header_length + len));
            }

            if (!was_fuzzed || fuzz_more) {
                was_fuzzed |= frame_header_fuzzer(fuzz_pilot, bytes, bytes_max, final_pad, header_length);
                if (!was_fuzzed) {
                    fuzzed_length = basic_packet_fuzzer(ctx, fuzz_pilot, bytes, bytes_max, length, header_length);
                }
            }

            if (icid_ctx->already_fuzzed == 0) {
                icid_ctx->already_fuzzed = 1;
                ctx->nb_cnx_tried[icid_ctx->target_state] += 1;
                ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
                if (fuzz_cnx_state == icid_ctx->target_state && icid_ctx->wait_count[fuzz_cnx_state] > ctx->waited_max[icid_ctx->target_state]) {
                    ctx->waited_max[icid_ctx->target_state] = icid_ctx->wait_count[fuzz_cnx_state];
                }
            }
            ctx->nb_packets_fuzzed[fuzz_cnx_state] += 1;
        }

        /* Mark the connection as active */
        if (ctx->parent != NULL) {
            /* Mark active */
            fuzi_q_mark_active(ctx->parent, &icid_ctx->icid, current_time, icid_ctx->already_fuzzed);
        }
    }

    return fuzzed_length;
}