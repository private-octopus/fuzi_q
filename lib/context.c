/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <picoquic.h>
#include <picoquic_internal.h>
#include <picoquic_utils.h>
#include <tls_api.h>
#include "fuzi_q.h"

/* Management of per connection context for fuzzing. */

static void* fuzi_q_icid_list_node_value(picosplay_node_t* icid_node)
{
    return (icid_node == NULL) ? NULL : (void*)((char*)icid_node - offsetof(struct st_fuzzer_icid_ctx_t, icid_node));
}

static int64_t fuzi_q_icid_list_compare(void* l, void* r) {
    int64_t ret = picoquic_compare_connection_id(&((fuzzer_icid_ctx_t*)l)->icid, &((fuzzer_icid_ctx_t*)r)->icid);
    return ret;
}

static picosplay_node_t* fuzi_q_icid_list_create_node(void* v_icid)
{
    return &((fuzzer_icid_ctx_t*)v_icid)->icid_node;
}

static void fuzi_q_icid_list_remove(fuzzer_ctx_t* ctx, fuzzer_icid_ctx_t* icid_ctx)
{
    /* Remove from chained LRU */
    if (icid_ctx->icid_after == NULL) {
        ctx->icid_lru = icid_ctx->icid_before;
    }
    else {
        icid_ctx->icid_after->icid_before = icid_ctx->icid_before;
    }
    if (icid_ctx->icid_before == NULL) {
        ctx->icid_mru = icid_ctx->icid_after;
    }
    else {
        icid_ctx->icid_before->icid_after = icid_ctx->icid_after;
    }

    icid_ctx->icid_after = NULL;
    icid_ctx->icid_before = NULL;
}

static void fuzi_q_icid_list_delete_node(void* tree, picosplay_node_t* node)
{
    /* remove from chained LRU, delete node */
    if (node != NULL){
        fuzzer_icid_ctx_t* icid_ctx = (fuzzer_icid_ctx_t*)fuzi_q_icid_list_node_value(node);
        if (tree != NULL) {
            fuzzer_ctx_t* ctx = (fuzzer_ctx_t*)((char*)tree - offsetof(struct st_fuzzer_ctx_t, icid_tree));
            fuzi_q_icid_list_remove(ctx, icid_ctx);
        }
        /* Delete node */
        free(icid_ctx);
    }
}

static void remove_last_icid_from_list(fuzzer_ctx_t * ctx)
{
    if (ctx->icid_lru != NULL) {
        picosplay_delete_hint(&ctx->icid_tree, &ctx->icid_lru->icid_node);
    }
}

static fuzzer_icid_ctx_t* create_icid_ctx(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid)
{
    fuzzer_icid_ctx_t* icid_ctx = (fuzzer_icid_ctx_t*)malloc(sizeof(fuzzer_icid_ctx_t));
    if (icid_ctx != NULL) {
        memset(icid_ctx, 0, sizeof(fuzzer_icid_ctx_t));
        (void)picoquic_parse_connection_id(icid->id, icid->id_len, &icid_ctx->icid);
        icid_ctx->random_context = picoquic_connection_id_hash(icid);
        /* Set the initial values, e.g. target state */
        uint64_t random_state = (icid_ctx->random_context ^ 0xdeadbeefc001cafeull) % fuzzer_cnx_state_max;
        uint64_t random_wait = (icid_ctx->random_context >> 2) ^ 0xa1a2a3a4a5a6a7a8ull;
        icid_ctx->target_state = (fuzzer_cnx_state_enum)random_state;
        icid_ctx->target_wait = ((int)random_wait) % (ctx->wait_max[icid_ctx->target_state]+1);
        if (ctx->icid_mru != NULL) {
            ctx->icid_mru->icid_before = icid_ctx;
            icid_ctx->icid_after = ctx->icid_mru;
        }
        ctx->icid_mru = icid_ctx;
        
        if (ctx->icid_lru == NULL) {
            ctx->icid_lru = icid_ctx;
        }
        (void)picosplay_insert(&ctx->icid_tree, icid_ctx);
    }
    return icid_ctx;
}

fuzzer_icid_ctx_t* fuzzer_get_icid_ctx(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid, uint64_t current_time)
{
    fuzzer_icid_ctx_t test = { 0 };
    picosplay_node_t* node;
    fuzzer_icid_ctx_t* icid_ctx = NULL;

    (void)picoquic_parse_connection_id(icid->id, icid->id_len, &test.icid);
    node = picosplay_find(&ctx->icid_tree, &test);
    if (node == NULL) {
        icid_ctx = create_icid_ctx(ctx, icid);
    }
    else {
        icid_ctx = (fuzzer_icid_ctx_t*)fuzi_q_icid_list_node_value(node);
    }

    if (icid_ctx != NULL) {
        icid_ctx->last_time = current_time;
        if (icid_ctx != ctx->icid_mru) {
            fuzi_q_icid_list_remove(ctx, icid_ctx);
            icid_ctx->icid_after = ctx->icid_mru;
            icid_ctx->icid_before = NULL;
            if (ctx->icid_mru != NULL) {
                ctx->icid_mru->icid_before = icid_ctx;
            }
            ctx->icid_mru = icid_ctx;
            if (ctx->icid_lru == NULL) {
                ctx->icid_lru = icid_ctx;
            }
        }
    }

    while (ctx->icid_lru != NULL && ctx->icid_lru->last_time + 2 * FUZI_Q_MAX_SILENCE < current_time) {
        remove_last_icid_from_list(ctx);
    }

    return icid_ctx;
}

/* Management of the fuzzer context itself.
 * Add definition of picoquic crypto random, so we can use it to 
 * initialize randomness when needed.
 */

void fuzi_q_fuzzer_init(fuzzer_ctx_t* fuzz_ctx, picoquic_connection_id_t * init_cid, picoquic_quic_t * quic)
{
    memset(fuzz_ctx, 0, sizeof(fuzzer_ctx_t));
    /* Initialize the tree of connection contexts */
    picosplay_init_tree(&fuzz_ctx->icid_tree, fuzi_q_icid_list_compare,
        fuzi_q_icid_list_create_node, fuzi_q_icid_list_delete_node, fuzi_q_icid_list_node_value);
    /* Set all wait_max to 1 */
    for (int i = 0; i < fuzzer_cnx_state_max; i++) {
        fuzz_ctx->wait_max[i] = 1;
    }
    /* Init CID. If not already set, initialize from random number */
    if (init_cid == NULL || init_cid->id_len == 0) {
        if (quic != NULL) {
            picoquic_crypto_random(quic, fuzz_ctx->next_cid.id, 8);
            fuzz_ctx->next_cid.id_len = 8;
        }
        else {
            picoquic_connection_id_t default_init_cid = { { 0xDE, 0xAD, 0xBE, 0xEF, 0xBA, 0xBA, 0xCA, 0xFE }, 8 };
            fuzz_ctx->next_cid = default_init_cid;
        }
    }
    else {
        fuzz_ctx->next_cid = *init_cid;
    }
}


/* Create a random CID as a hash of the previous one.
 * This is useful for ensuring that the client tests are repeatable.
 */

void fuzzer_random_cid(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid)
{
    /* Set a hash context for derivation of random CID */
    void * hash_context = picoquic_hash_create("sha256");
    uint8_t hash_buffer[256] = { 0 };
    /* Use the CID that was already prepared */
    *icid = ctx->next_cid;
    /* Derive the next CID from the previous value using SHA 256 */
    picoquic_hash_update((uint8_t *)"fuzi_q", 6, hash_context);
    picoquic_hash_update(ctx->next_cid.id, ctx->next_cid.id_len, hash_context);
    picoquic_hash_finalize(hash_buffer, hash_context);
    memcpy(ctx->next_cid.id, hash_buffer, ctx->next_cid.id_len);
}

/* Release the fuzzer context */
void fuzi_q_fuzzer_release(fuzzer_ctx_t* fuzz_ctx)
{
    picosplay_empty_tree(&fuzz_ctx->icid_tree);
}