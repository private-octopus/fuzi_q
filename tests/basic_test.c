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

#include <stdlib.h>
#include <string.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_set_textlog.h>
#include <picoquic_set_binlog.h>
#include <picoquic_config.h>
#include <autoqlog.h>

#include "fuzi_q.h"
#include "fuzi_q_tests.h"
#ifdef _WINDOWS
#ifdef _WINDOWS64
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\..\\picoquic\\"
#define fuzi_q_DEFAULT_SOLUTION_DIR "..\\..\\"
#else
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\picoquic\\"
#define fuzi_q_DEFAULT_SOLUTION_DIR "..\\"
#endif
#else
#define fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR "../picoquic/"
#define fuzi_q_DEFAULT_SOLUTION_DIR "./"
#endif

char const* fuzi_q_test_picoquic_solution_dir = fuzi_q_PICOQUIC_DEFAULT_SOLUTION_DIR;
char const* fuzi_q_test_solution_dir = fuzi_q_DEFAULT_SOLUTION_DIR;


typedef struct st_fuzi_q_test_attach_t {
    int node_id;
    int link_id;
    struct sockaddr_storage node_addr;
} fuzi_q_test_attach_t;

typedef struct st_fuzi_q_test_config_t {
    uint64_t simulated_time;
    uint64_t simulate_loss;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    uint8_t ticket_encryption_key[16];
    int nb_nodes; /* should be 2 in default configuration  */
    fuzi_q_ctx_t* nodes;
    int nb_links; /* should be 2 in default configuration  */
    picoquictest_sim_link_t** links;
    int* return_links;
    int nb_attachments; /* should be 2 in default configuration  */
    fuzi_q_test_attach_t* attachments;
    uint64_t cnx_error_client;
    uint64_t cnx_error_server;
} fuzi_q_test_config_t;

/* Find arrival context by link ID and destination address */
int fuzi_q_test_find_dest_node(fuzi_q_test_config_t* config, int link_id, struct sockaddr* addr)
{
    int node_id = -1;

    for (int d_attach = 0; d_attach < config->nb_attachments; d_attach++) {
        if (config->attachments[d_attach].link_id == link_id &&
            picoquic_compare_addr((struct sockaddr*)&config->attachments[d_attach].node_addr, addr) == 0) {
            node_id = config->attachments[d_attach].node_id;
            break;
        }
    }
    return (node_id);
}

/* Find departure link by destination address.
 * The code verifies that the return link is present.
 * If srce_addr is prsent and set to AF_UNSPEC, it is filled with appropriate address.
 */
int fuzi_q_test_find_send_link(fuzi_q_test_config_t* config, int srce_node_id, const struct sockaddr* dest_addr, struct sockaddr_storage* srce_addr)
{
    int dest_link_id = -1;

    for (int s_attach = 0; s_attach < config->nb_attachments && dest_link_id == -1; s_attach++) {
        if (config->attachments[s_attach].node_id == srce_node_id) {
            int link_id = config->return_links[config->attachments[s_attach].link_id];
            for (int d_attach = 0; d_attach < config->nb_attachments; d_attach++) {
                if (config->attachments[d_attach].link_id == link_id &&
                    picoquic_compare_addr((struct sockaddr*)&config->attachments[d_attach].node_addr, dest_addr) == 0) {
                    if (srce_addr != NULL && srce_addr->ss_family == AF_UNSPEC) {
                        picoquic_store_addr(srce_addr, (struct sockaddr*)&config->attachments[s_attach].node_addr);
                    }
                    dest_link_id = config->attachments[d_attach].link_id;
                    break;
                }
            }
        }
    }

    return dest_link_id;
}

/* Find destination address from source and destination node id. */
struct sockaddr* fuzi_q_test_find_send_addr(fuzi_q_test_config_t* config, int srce_node_id, int dest_node_id)
{
    struct sockaddr* dest_addr = NULL;
    for (int s_attach = 0; s_attach < config->nb_attachments && dest_addr == NULL; s_attach++) {
        if (config->attachments[s_attach].node_id == srce_node_id) {
            int link_id = config->return_links[config->attachments[s_attach].link_id];
            for (int d_attach = 0; d_attach < config->nb_attachments; d_attach++) {
                if (config->attachments[d_attach].link_id == link_id &&
                    config->attachments[d_attach].node_id == dest_node_id) {
                    dest_addr = (struct sockaddr*)&config->attachments[d_attach].node_addr;
                    break;
                }
            }
        }
    }

    return dest_addr;
}

/* Packet departure from selected node */
int fuzi_q_test_packet_departure(fuzi_q_test_config_t* config, int node_id, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(config->nodes[node_id].quic, config->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL, NULL);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            free(packet);
            ret = -1;
        }
        else if (packet->length > 0) {
            /* Find the exit link. This assumes destination addresses are available on only one link */
            int link_id = fuzi_q_test_find_send_link(config, node_id, (struct sockaddr*)&packet->addr_to, &packet->addr_from);

            if (link_id >= 0) {
                *is_active = 1;
                picoquictest_sim_link_submit(config->links[link_id], packet, config->simulated_time);
            }
            else {
                /* packet cannot be routed. */
                free(packet);
            }
        }
    }

    return ret;
}

int fuzi_q_test_post_departure(fuzi_q_test_config_t* config, int node_id, int* is_active)
{
    fuzi_q_ctx_t * fuzi_q_ctx = &config->nodes[node_id];
    int ret = 0;

    if (fuzi_q_ctx->fuzz_mode == fuzi_q_mode_client ||
        fuzi_q_ctx->fuzz_mode == fuzi_q_mode_clean) {
        ret = fuzi_q_loop_check_cnx(fuzi_q_ctx, config->simulated_time, is_active);
    }

    return ret;
}

/* Process arrival of a packet from a link */
int fuzi_q_test_packet_arrival(fuzi_q_test_config_t* config, int link_id, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(config->links[link_id], config->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        int node_id = fuzi_q_test_find_dest_node(config, link_id, (struct sockaddr*)&packet->addr_to);
        uint64_t loss = (config->simulate_loss & 1);
        config->simulate_loss >>= 1;
        config->simulate_loss |= (loss << 63);

        if (node_id >= 0 && loss == 0) {
            *is_active = 1;

            ret = picoquic_incoming_packet(config->nodes[node_id].quic,
                packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
                config->simulated_time);
        }
        else {
            /* simulated loss */
        }
        free(packet);
    }

    return ret;
}

/* Execute the loop */
int fuzi_q_test_loop_step(fuzi_q_test_config_t* config, int* is_active)
{
    int ret = 0;
    int next_step_type = 0;
    int next_step_index = 0;
    uint64_t next_time = UINT64_MAX;

    /* Check which node has the lowest wait time */
    for (int i = 0; i < config->nb_nodes; i++) {
        /* Look at both quic timer and fuzi level timer */
        uint64_t quic_time = picoquic_get_next_wake_time(config->nodes[i].quic, config->simulated_time);
        uint64_t fuzz_time = fuzi_q_next_time(&config->nodes[i]);
        if (quic_time > fuzz_time) {
            quic_time = fuzz_time;
        }
        if (quic_time < next_time) {
            next_time = quic_time;
            next_step_type = 1;
            next_step_index = i;
        }
    }
    /* Check which link has the lowest arrival time */
    for (int i = 0; i < config->nb_links; i++) {
        if (config->links[i]->first_packet != NULL &&
            config->links[i]->first_packet->arrival_time < next_time) {
            next_time = config->links[i]->first_packet->arrival_time;
            next_step_type = 2;
            next_step_index = i;
        }
    }
    if (next_time < UINT64_MAX) {
        /* Update the time */
        if (next_time > config->simulated_time) {
            config->simulated_time = next_time;
        }
        switch (next_step_type) {
        case 1: /* context #next_step_index is ready to send data */
            ret = fuzi_q_test_packet_departure(config, next_step_index, is_active);
            if (ret == 0) {
                ret = fuzi_q_test_post_departure(config, next_step_index, is_active);
            }
            break;
        case 2:
            /* If arrival, take next packet, find destination by address, and submit to end-of-link context */
            ret = fuzi_q_test_packet_arrival(config, next_step_index, is_active);
            break;
        default:
            /* This should never happen! */
            ret = -1;
            break;
        }
    }
    else {
        ret = -1;
    }

    return ret;
}

/* Delete a configuration */
void fuzi_q_test_config_delete(fuzi_q_test_config_t* config)
{
    if (config->nodes != NULL) {
        for (int i = 0; i < config->nb_nodes; i++) {
            fuzi_q_release_client_context(&config->nodes[i]);
        }
        free(config->nodes);
    }

    if (config->links != NULL) {
        for (int i = 0; i < config->nb_links; i++) {
            if (config->links[i] != NULL) {
                picoquictest_sim_link_delete(config->links[i]);
            }
        }
        free(config->links);
    }

    if (config->return_links != NULL) {
        free(config->return_links);
    }

    if (config->attachments != NULL) {
        free(config->attachments);
    }

    free(config);
}

/* Create a configuration */
fuzi_q_test_config_t* fuzi_q_test_config_create(int nb_nodes, int nb_links, int nb_attachments, int nb_sources)
{
    fuzi_q_test_config_t* config = (fuzi_q_test_config_t*)malloc(sizeof(fuzi_q_test_config_t));

    if (config != NULL) {
        int success = 1;

        memset(config, 0, sizeof(fuzi_q_test_config_t));
        memset(config->ticket_encryption_key, 0x55, sizeof(config->ticket_encryption_key));

        /* Locate the default cert, key and root in the Picoquic solution*/
        if (picoquic_get_input_path(config->test_server_cert_file, sizeof(config->test_server_cert_file),
            fuzi_q_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT) != 0 ||
            picoquic_get_input_path(config->test_server_key_file, sizeof(config->test_server_key_file),
                fuzi_q_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY) != 0 ||
            picoquic_get_input_path(config->test_server_cert_store_file, sizeof(config->test_server_cert_store_file),
                fuzi_q_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE) != 0) {
            success = 0;
        }

        if (nb_nodes <= 0 || nb_nodes > 0xffff) {
            success = 0;
        }
        else if (success) {
            config->nodes = (fuzi_q_ctx_t*)malloc(nb_nodes * sizeof(fuzi_q_ctx_t));
            success &= (config->nodes != NULL);
            if (success) {
                memset(config->nodes, 0, nb_nodes * sizeof(fuzi_q_ctx_t));
                config->nb_nodes = nb_nodes;
            }
        }

        if (nb_links <= 0 || nb_links > 0xffff) {
            success = 0;
        }
        else if (success) {
            config->links = (picoquictest_sim_link_t**)malloc(nb_links * sizeof(picoquictest_sim_link_t*));
            config->return_links = (int*)malloc(nb_links * sizeof(int));
            success &= (config->links != NULL);

            if (success) {
                memset(config->links, 0, nb_links * sizeof(picoquictest_sim_link_t*));
                config->nb_links = nb_links;

                for (int i = 0; success && (i < nb_links); i++) {
                    picoquictest_sim_link_t* link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, config->simulated_time);
                    config->links[i] = link;
                    success &= (link != NULL);
                }
            }
        }


        if (nb_attachments <= 0 || nb_attachments > 0xffff) {
            success = 0;
        }
        else if (success) {
            config->attachments = (fuzi_q_test_attach_t*)malloc(nb_attachments * sizeof(fuzi_q_test_attach_t));
            success &= (config->attachments != NULL);

            if (success) {
                memset(config->attachments, 0, nb_attachments * sizeof(fuzi_q_test_attach_t));
                config->nb_attachments = nb_attachments;
                for (int i = 0; success && (i < config->nb_attachments); i++) {
                    char addr_text[128];
                    fuzi_q_test_attach_t* p_attach = &config->attachments[i];

                    if (picoquic_sprintf(addr_text, sizeof(addr_text), NULL, "%x::%x", i + 0x1000, i + 0x1000) == 0) {
                        picoquic_store_text_addr(&p_attach->node_addr, addr_text, i + 0x1000);
                    }
                    else {
                        success = 0;
                    }
                }
            }
        }

        if (!success) {
            fuzi_q_test_config_delete(config);
            config = NULL;
        }
    }

    return config;
}

int fuzi_q_set_test_client_ctx(fuzi_q_test_config_t* test_config, fuzi_q_ctx_t* fuzi_q_ctx, fuzi_q_mode_enum fuzz_mode,
    size_t nb_cnx_ctx, size_t nb_cnx_required, uint64_t duration_max, char const * client_scenario_text, 
    struct sockaddr* server_addr, char const * qlog_dir)
{
    int ret = 0;
    uint64_t current_time = test_config->simulated_time; 
    static const char* test_scenario_default = "0:index.html;4:0:/1000;8:4:/12345";
    picoquic_quic_config_t config = { 0 };
    config.nb_connections = (uint32_t)(2*nb_cnx_ctx);
    config.cnx_id_length = 8;

    fuzi_q_ctx->fuzz_mode = fuzz_mode;
    fuzi_q_ctx->config = NULL;
    fuzi_q_ctx->up_time_interval = 60000000; /* Use 1 minute by default -- hanshake timer is set to 30 seconds. */
    fuzi_q_ctx->cnx_duration_min = UINT64_MAX;

    fuzi_q_ctx->end_of_time = (duration_max == 0) ? UINT64_MAX : current_time + duration_max * 1000000;
    fuzi_q_ctx->nb_cnx_required = (nb_cnx_required == 0) ? SIZE_MAX : nb_cnx_required;
    fuzi_q_ctx->next_success_time = current_time + fuzi_q_ctx->up_time_interval;

    if (fuzi_q_ctx->alpn != NULL && strcmp(fuzi_q_ctx->alpn, QUICPERF_ALPN) == 0) {
        /* Set a QUICPERF client */
        fuzi_q_ctx->is_quicperf = 1;
        fprintf(stdout, "Getting ready to fuzz QUICPERF server\n");
    }
    else {
        if (client_scenario_text == NULL) {
            client_scenario_text = test_scenario_default;
        }

        fprintf(stdout, "Testing scenario: <%s>\n", client_scenario_text);
        ret = demo_client_parse_scenario_desc(client_scenario_text, &fuzi_q_ctx->client_sc_nb, &fuzi_q_ctx->client_sc);
        if (ret != 0) {
            fprintf(stdout, "Cannot parse the specified scenario.\n");
        }
    }

    /* Create QUIC context */
    if (ret == 0) {
        fuzi_q_ctx->quic = picoquic_create_and_configure(&config, NULL, NULL, current_time, &test_config->simulated_time);
        if (fuzi_q_ctx->quic == NULL) {
            ret = -1;
        }
        else {
            fuzi_q_fuzzer_init(&fuzi_q_ctx->fuzz_ctx, NULL, NULL);
            fuzi_q_ctx->fuzz_ctx.parent = fuzi_q_ctx;
            if (fuzz_mode != fuzi_q_mode_clean) {
                picoquic_set_fuzz(fuzi_q_ctx->quic, fuzi_q_fuzzer, &fuzi_q_ctx->fuzz_ctx);
            }

            if (qlog_dir != NULL) {
                picoquic_set_qlog(fuzi_q_ctx->quic, qlog_dir);
            }
        }
    }

    /* Create empty connection contexts */
    if (ret == 0) {
        picoquic_store_addr(&fuzi_q_ctx->server_address, server_addr);
        fuzi_q_ctx->cnx_ctx = (fuzi_q_cnx_ctx_t*)malloc(sizeof(fuzi_q_cnx_ctx_t) * nb_cnx_ctx);
        if (fuzi_q_ctx->cnx_ctx == NULL) {
            ret = -1;
        }
        else {
            memset(fuzi_q_ctx->cnx_ctx, 0, sizeof(fuzi_q_cnx_ctx_t) * nb_cnx_ctx);
            fuzi_q_ctx->nb_cnx_ctx = nb_cnx_ctx;
        }
    }

    /* Initialize the client connections */
    if (ret == 0) {
        int is_active = 0;
        ret = fuzi_q_loop_check_cnx(fuzi_q_ctx, current_time, &is_active);
    }

    return ret;
}

int fuzi_q_set_test_server_ctx(fuzi_q_test_config_t* test_config, fuzi_q_ctx_t* fuzi_q_ctx, fuzi_q_mode_enum fuzz_mode,
    size_t nb_cnx_ctx, uint64_t duration_max, struct sockaddr* server_addr, char const* qlog_dir)
{
    int ret = 0;
    picoquic_quic_config_t config = { 0 };
    config.nb_connections = (uint32_t)(4*nb_cnx_ctx);
    config.server_cert_file = test_config->test_server_cert_file;
    config.server_key_file = test_config->test_server_key_file;
    config.cnx_id_length = 8;

    if (server_addr != NULL) {
        if (server_addr->sa_family == AF_INET) {
            config.server_port = ((struct sockaddr_in*)server_addr)->sin_port;
        }
        else if (server_addr->sa_family == AF_INET) {
            config.server_port = ((struct sockaddr_in6*)server_addr)->sin6_port;
        }
    }

    fuzi_q_ctx->quic = picoquic_create_and_configure(&config, picoquic_demo_server_callback, NULL, test_config->simulated_time,
        &test_config->simulated_time);
    if (fuzi_q_ctx->quic == NULL) {
        ret = -1;
    }
    else {
        fuzi_q_ctx->fuzz_mode = fuzz_mode;
        fuzi_q_fuzzer_init(&fuzi_q_ctx->fuzz_ctx, NULL, NULL);
        if (fuzz_mode != fuzi_q_mode_clean_server) {
            picoquic_set_fuzz(fuzi_q_ctx->quic, fuzi_q_fuzzer, &fuzi_q_ctx->fuzz_ctx);
        }

        picoquic_set_alpn_select_fn(fuzi_q_ctx->quic, picoquic_demo_server_callback_select_alpn);

        picoquic_set_mtu_max(fuzi_q_ctx->quic, PICOQUIC_MAX_PACKET_SIZE);

        if (qlog_dir != NULL)
        {
            picoquic_set_qlog(fuzi_q_ctx->quic, qlog_dir);
        }
    }

    return ret;
}

fuzi_q_test_config_t* fuzi_q_test_basic_config_create(uint64_t simulate_loss, fuzi_q_mode_enum client_fuzz_mode, fuzi_q_mode_enum server_fuzz_mode,
    size_t nb_cnx_ctx, size_t nb_cnx_required, uint64_t duration_max, char const* client_scenario_text, char const* qlog_dir)
{
    /* Create a configuration with just two nodes, two links, one source and two attachment points.*/
    fuzi_q_test_config_t* config = fuzi_q_test_config_create(2, 2, 2, 1);
    struct sockaddr* server_addr = NULL;
    int a_ret = 0;
    int s_ret = 0;
    int c_ret = 0;

    if (config != NULL) {
        /* Populate the attachments */
        config->return_links[0] = 1;
        config->attachments[0].link_id = 0;
        config->attachments[0].node_id = 0;
        config->return_links[1] = 0;
        config->attachments[1].link_id = 1;
        config->attachments[1].node_id = 1;
        /* Set the desired loss pattern */
        config->simulate_loss = simulate_loss;

        /* Find the server address */
        server_addr = fuzi_q_test_find_send_addr(config, 1, 0);
        if (server_addr == NULL) {
            a_ret = -1;
        }
        else {
            /* configure server on nodes[0], client on nodes[1].
             * Apply fuzz_mode to client and to server
             */
            s_ret = fuzi_q_set_test_server_ctx(config, &config->nodes[0], server_fuzz_mode,
                nb_cnx_ctx, duration_max, server_addr, qlog_dir);
            c_ret = fuzi_q_set_test_client_ctx(config, &config->nodes[1], client_fuzz_mode,
                nb_cnx_ctx, nb_cnx_required, duration_max, client_scenario_text,
                server_addr, qlog_dir);
        }
        if (a_ret != 0 || s_ret != 0 || c_ret != 0) {
            DBG_PRINTF("Configuration failed, address: %d, server: %d, client: %d", a_ret, s_ret, c_ret);
            fuzi_q_test_config_delete(config);
            config = NULL;
        }
    }
    return config;
}

int fuzi_q_test_check_fuzz(size_t nb_cnx_required, fuzzer_ctx_t * fuzz_ctx)
{
    size_t total_tried = 0;
    int ret = 0;

    for (int i = 0; ret == 0 && i < fuzzer_cnx_state_max; i++)
    {
        total_tried += fuzz_ctx->nb_cnx_tried[i];
        if (fuzz_ctx->nb_cnx_tried[i] == 0) {
            DBG_PRINTF("No trials for connection fuzzing state %d", i);
            ret = -1;
        }
        else if (fuzz_ctx->nb_cnx_tried[i] != fuzz_ctx->nb_cnx_fuzzed[i]) {
            DBG_PRINTF("Connection fuzzing state % d, tried %zu, fuzzed %zu", i,
                fuzz_ctx->nb_cnx_tried[i], fuzz_ctx->nb_cnx_fuzzed[i]);
            ret = -1;
        }
    }
    if (total_tried != nb_cnx_required) {
        DBG_PRINTF("Tried %zu instead of %zu", total_tried, nb_cnx_required);
        ret = -1;
    }
    return ret;
}

/* Basic loop, supporting 4 variations */
int fuzi_q_basic_test_loop(int fuzz_client, int fuzz_server, int simulate_loss)
{
    int ret = 0;
    fuzi_q_mode_enum client_fuzz_mode = (fuzz_client) ? fuzi_q_mode_client : fuzi_q_mode_clean;
    fuzi_q_mode_enum server_fuzz_mode = (fuzz_server) ? fuzi_q_mode_server : fuzi_q_mode_clean_server;
    int nb_steps = 0;
    int nb_inactive = 0;
    size_t nb_cnx_required = 16;
    const uint64_t max_time = 360000000;
    const int max_inactive = 128;
    fuzi_q_test_config_t* config = fuzi_q_test_basic_config_create(simulate_loss, client_fuzz_mode, server_fuzz_mode,
        4, nb_cnx_required, 360000000, NULL, ".");

    while (ret == 0 && nb_inactive < max_inactive && config->simulated_time < max_time) {
        /* Run the simulation. Monitor the connection. Monitor the media. */
        int is_active = 0;

        ret = fuzi_q_test_loop_step(config, &is_active);
        if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
            ret = 0;
            break;
        }

        if (ret != 0) {
            DBG_PRINTF("Fail on loop step %d, %d, active: ret=%d", nb_steps, is_active, ret);
            break;
        }

        nb_steps++;

        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
            if (nb_inactive >= max_inactive) {
                DBG_PRINTF("Exit loop after too many inactive: %d", nb_inactive);
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0) {
        fuzi_q_ctx_t* fuzi_q_ctx = &config->nodes[1];
        if (fuzi_q_ctx->server_is_down) {
            DBG_PRINTF("Server down at time %" PRIu64, config->simulated_time);
            ret = -1;
        }
        else if (fuzi_q_ctx->nb_cnx_tried != nb_cnx_required) {
            DBG_PRINTF("Tried %zu connections instead of %zu" PRIu64, fuzi_q_ctx->nb_cnx_tried, nb_cnx_required);
            ret = -1;
        }
        else if (client_fuzz_mode == fuzi_q_mode_client) {
            ret = fuzi_q_test_check_fuzz(nb_cnx_required, &fuzi_q_ctx->fuzz_ctx);
        }
    }

    /* Clear everything. */
    if (config != NULL) {
        fuzi_q_test_config_delete(config);
    }

    return ret;
}


/* Basic test, place holder for now. */
int fuzi_q_basic_test()
{
    return fuzi_q_basic_test_loop(0,0,0);
}

/* Basic test, place holder for now. */
int fuzi_q_basic_client_test()
{
    return fuzi_q_basic_test_loop(1, 0, 0);
}