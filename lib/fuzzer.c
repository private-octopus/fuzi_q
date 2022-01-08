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

#define FUZZER_MAX_NB_FRAMES 32

int frame_header_fuzzer(uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    uint8_t* frame_head[FUZZER_MAX_NB_FRAMES];
    size_t frame_length[FUZZER_MAX_NB_FRAMES];
    uint8_t* last_byte = bytes + bytes_max;
    size_t nb_frames = 0;
    int was_fuzzed = 0;

    bytes += header_length;

    while (bytes != NULL && bytes < last_byte && nb_frames < FUZZER_MAX_NB_FRAMES) {
        size_t consumed = 0;
        int is_pure_ack = 1;
        uint8_t first_byte = *bytes;
        frame_head[nb_frames] = bytes;
        if (picoquic_skip_frame(bytes, last_byte - bytes, &consumed, &is_pure_ack) == 0) {
            bytes += consumed;
            frame_length[nb_frames] = consumed;
            nb_frames++;
        }
        else {
            bytes = NULL;
        }
    }

    if (nb_frames > 0) {
        size_t fuzzed_frame = (size_t)(fuzz_pilot % nb_frames);
        uint8_t* frame_byte = frame_head[fuzzed_frame];
        size_t fuzz_max = (frame_length[fuzzed_frame] > 9) ? 9 : frame_length[fuzzed_frame];
        size_t fuzz_index = (fuzz_max > 1) ? (size_t)((fuzz_pilot >> 5) % (fuzz_max - 1)) + 1 : 0;
        fuzz_pilot >>= 8;
        while (fuzz_pilot != 0 && fuzz_index < fuzz_max) {
            /* flip one byte */
            frame_byte[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
            fuzz_pilot >>= 8;
            was_fuzzed = 1;
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
    int should_fuzz = 0;
    int should_fuzz_initial = 0;
    uint32_t fuzz_index = 0;
    fuzzer_cnx_state_enum fuzz_cnx_state = fuzzer_get_cnx_state(cnx);
    uint32_t fuzzed_length = (uint32_t)length;
    int fuzz_again = ((fuzz_pilot & 0xf) <= 7);

    if (fuzz_cnx_state < 0 || fuzz_cnx_state > fuzzer_cnx_state_max) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }

    fuzz_pilot >>= 4;

    if (icid_ctx != NULL) {
        ctx->nb_packets++;
        ctx->nb_packets_state[fuzz_cnx_state] += 1;
        /* Only perform fuzzing if the connection has reached or passed the target state */
        if (fuzz_cnx_state >= icid_ctx->target_state && (!icid_ctx->already_fuzzed || fuzz_again)) {
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