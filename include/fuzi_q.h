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

#define FUZI_Q_MAX_SILENCE 3000000

/* Operation modes for the fuzzer
 */
typedef enum {
    fuzi_q_mode_none = 0,
    fuzi_q_mode_server,
    fuzi_q_mode_client,
    fuzi_q_mode_clean,
    fuzi_q_mode_clean_server
} fuzi_q_mode_enum;

/* Fuzzing context per connection. The goals are:
 * - Ensure fuzzing in all connection states, which implies specializing
 *   some connections as for example "fuzzing the handhake" or "fuzzing
 *   the closing state".
 * - Allows for repeatability, which we obtain by using the initial connection
 *   ID as seed for the fuzzing sequence.
 * - Work well in either a "client" or "server" setup, which means making
 *   no assumption on connection ID structure, apart from randomness, and
 *   also implies using LRU management of the connection list.
 * - Be reasonably fast, which is achieved by using a hash table for
 *   accessing the contexts.
 */

typedef enum {
    fuzzer_cnx_state_initial = 0,
    fuzzer_cnx_state_not_ready,
    fuzzer_cnx_state_ready,
    fuzzer_cnx_state_closing,
    fuzzer_cnx_state_max
} fuzzer_cnx_state_enum;

typedef struct st_fuzzer_icid_ctx_t {
    picosplay_node_t icid_node;
    struct st_fuzzer_icid_ctx_t* icid_before;
    struct st_fuzzer_icid_ctx_t* icid_after;
    picoquic_connection_id_t icid;
    uint64_t last_time;
    uint64_t random_context;
    fuzzer_cnx_state_enum target_state;
    int target_wait;
    int wait_count[fuzzer_cnx_state_max];
    int already_fuzzed;
} fuzzer_icid_ctx_t;

typedef struct st_fuzzer_ctx_t {
    picosplay_tree_t icid_tree;
    fuzzer_icid_ctx_t* icid_mru;
    fuzzer_icid_ctx_t* icid_lru;
    struct st_fuzi_q_ctx_t* parent;
    picoquic_connection_id_t next_cid;
    size_t nb_cnx_tried[fuzzer_cnx_state_max];
    size_t nb_cnx_fuzzed[fuzzer_cnx_state_max];
    size_t nb_packets_fuzzed[fuzzer_cnx_state_max];
    size_t nb_packets_state[fuzzer_cnx_state_max];
    int wait_max[fuzzer_cnx_state_max];
    int waited_max[fuzzer_cnx_state_max];
    uint32_t nb_packets;
    uint32_t nb_fuzzed;
    uint32_t nb_fuzzed_length;
} fuzzer_ctx_t;

fuzzer_icid_ctx_t* fuzzer_get_icid_ctx(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid, uint64_t current_time);

/* Test frames for use in fuzzing.
 */
typedef struct st_fuzi_q_frames_t {
    char const* name;
    uint8_t* val;
    size_t len;
} fuzi_q_frames_t;

extern fuzi_q_frames_t fuzi_q_frame_list[];
extern size_t nb_fuzi_q_frame_list;

/*
* Fuzz test, merge of basic fuzzer and initial fuzzer from picoquic tests
*/

uint32_t fuzi_q_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length);
void fuzzer_random_cid(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid);
void fuzi_q_fuzzer_init(fuzzer_ctx_t* fuzz_ctx, picoquic_connection_id_t* init_cid, picoquic_quic_t* quic);
void fuzi_q_fuzzer_release(fuzzer_ctx_t* fuzz_ctx);

/* Unification of initial and basic fuzzer
 * TODO: merge the two mechanisms in a single state
 */

typedef struct st_fuzi_q_cnx_ctx_t {
    /* Data required to start client connections */
    picoquic_cnx_t* cnx_client;
    picoquic_connection_id_t icid;
    picoquic_demo_callback_ctx_t callback_ctx;
    quicperf_ctx_t* quicperf_ctx;
    uint64_t next_time;
    int zero_rtt_available;
    int success_observed;
    int was_fuzzed;
} fuzi_q_cnx_ctx_t;

typedef struct st_fuzi_q_ctx_t {
    fuzi_q_mode_enum fuzz_mode;
    picoquic_quic_config_t* config;
    picoquic_quic_t* quic;
    /* Data used by client and server */
    const char* sni;
    const char* alpn;
    size_t socket_buffer_size;
    char const* out_dir;
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
    uint64_t cnx_duration_min;
    uint64_t cnx_duration_max;
    picoquic_connection_id_t icid_duration_max;
    /* Management of fuzzing. */
    fuzzer_ctx_t fuzz_ctx;
} fuzi_q_ctx_t;

int fuzi_q_server(fuzi_q_mode_enum fuzz_mode, picoquic_quic_config_t* config, uint64_t duration_max);
int fuzi_q_client(fuzi_q_mode_enum fuzz_mode, const char* ip_address_text, int server_port,
    picoquic_quic_config_t* config, size_t nb_cnx_required, uint64_t duration_max,
    picoquic_connection_id_t* init_cid, char const* client_scenario_text);
void fuzi_q_release_client_context(fuzi_q_ctx_t* fuzi_q_ctx);
void fuzi_q_mark_active(fuzi_q_ctx_t* fuzi_q_ctx, picoquic_connection_id_t* icid, uint64_t current_time, int was_fuzzed);
uint64_t fuzi_q_next_time(fuzi_q_ctx_t* fuzi_q_ctx);
int fuzi_q_loop_check_cnx(fuzi_q_ctx_t* fuzi_q_ctx, uint64_t current_time, int * is_active);
void fuzzer_random_cid(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid);

#ifdef __cplusplus
}
#endif


#endif /* FUZI_Q_H */
