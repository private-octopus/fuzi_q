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

#ifndef FUZI_Q_H
#define FUZI_Q_H

#include <stdint.h>
#include <picoquic.h>
#include <picosplay.h>
#include <quicperf.h>
#include <h3zero.h>
#include <democlient.h>
#include <demoserver.h>
#include <picoquic_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Operation modes for the fuzzer
 */
typedef enum {
    fuzi_q_mode_none = 0,
    fuzi_q_mode_server,
    fuzi_q_mode_client,
    fuzi_q_mode_clean
} fuzi_q_mode_enum;

/*
* Initial fuzz test.
*
* This test specializes in fuzzing the initial packet, and checking what happens. All the
* packets sent there are illegitimate, and should result in broken connections.
*
* The test reuses the frame definitions of the skip frame test library from picoquic.
*/

typedef struct st_initial_fuzzer_ctx_t {
    uint32_t current_frame;
    uint32_t fuzz_position;
    int initial_fuzzing_done;
    uint64_t random_context;
} initial_fuzzer_ctx_t;

uint32_t initial_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length);

/*
* Basic fuzz test just tries to flip some bits in random packets
*/

typedef struct st_basic_fuzzer_ctx_t {
    uint32_t nb_packets;
    uint32_t nb_fuzzed;
    uint32_t nb_fuzzed_length;
    uint64_t random_context;
    picoquic_state_enum highest_state_fuzzed;
} basic_fuzzer_ctx_t;

uint32_t basic_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length);

void basic_fuzzer_init(basic_fuzzer_ctx_t* fuzz_ctx, uint64_t tweak);

/* Unification of initial and basic fuzzer
 * TODO: merge the two mechanisms in a single state
 */

typedef struct st_fuzi_q_cnx_ctx_t {
    /* Data required to start client connections */
    picoquic_cnx_t* cnx_client;
    picoquic_demo_callback_ctx_t callback_ctx;
    quicperf_ctx_t* quicperf_ctx;
    int zero_rtt_available;
    int success_observed;
} fuzi_q_cnx_ctx_t;

typedef struct st_fuzi_q_ctx_t {
    fuzi_q_mode_enum fuzz_mode;
    picoquic_quic_config_t* config;
    picoquic_quic_t* quic;
    /* Data used by client and server */
    const char* sni;
    const char* alpn;
    size_t socket_buffer_size;
    /* Data required to start client connections */
    struct sockaddr_storage server_address;
    char const* client_scenario_text;
    size_t client_sc_nb;
    picoquic_demo_stream_desc_t* client_sc;
    uint64_t end_of_time;
    uint64_t up_time_interval;
    uint64_t next_success_time;
    fuzi_q_cnx_ctx_t* cnx_ctx;
    size_t nb_cnx_ctx;
    size_t nb_cnx_tried;
    size_t nb_cnx_required;
    uint32_t proposed_version;
    uint32_t desired_version;
    int is_quicperf;
    int server_is_down;
    /* Management of fuzzing. */
    basic_fuzzer_ctx_t fuzz_ctx;
} fuzi_q_ctx_t;

int fuzi_q_server(fuzi_q_mode_enum fuzz_mode, picoquic_quic_config_t* config, uint64_t duration_max);
int fuzi_q_client(fuzi_q_mode_enum fuzz_mode, const char* ip_address_text, int server_port,
    picoquic_quic_config_t* config, size_t nb_cnx_required, uint64_t duration_max,
    char const* client_scenario_text);

#ifdef __cplusplus
}
#endif


#endif /* FUZI_Q_H */
