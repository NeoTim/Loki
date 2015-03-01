/*
 *      ospf.c
 * 
 *      Copyright 2015 Daniel Mende <dmende@ernw.de>
 */

/*
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of the  nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>

#include <bf.h>
#include <bf/ospf.h>

static void ospf_bf_md5_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    ospf_md5_data_t *data = (ospf_md5_data_t *) proto_data;
    md5_init(&data->base);
    md5_append(&data->base, (const md5_byte_t *) pre_hash_data, pre_hash_data_len);
}

static int ospf_bf_md5_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    ospf_md5_data_t *data = (ospf_md5_data_t *) proto_data;
    md5_state_t cur;
    md5_byte_t digest[16];
    
    memset(digest, 0, 16);
    memcpy(digest, secret, strlen(secret));
    memcpy((void *) &cur, &data->base, sizeof(md5_state_t));
    md5_append(&cur, digest, 16);
    md5_finish(&cur, digest);
    if(!memcmp(hash_data, digest, 16))
        return 1;
    return 0;
}

bf_error ospf_bf_md5_state_new(bf_state_t **state) {
    bf_error error;
    ospf_md5_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(ospf_md5_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, ospf_bf_md5_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, ospf_bf_md5_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}

static void ospf_bf_hmac_sha1_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    ospf_hmac_sha1_data_t *data = (ospf_hmac_sha1_data_t *) proto_data;
    data->data = pre_hash_data;
    data->data_len = pre_hash_data_len;
}

static int ospf_bf_hmac_sha1_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    ospf_hmac_sha1_data_t *data = (ospf_hmac_sha1_data_t *) proto_data;
    sha1nfo ctx, ctx2;
    uint8_t *result;
    uint8_t key[20];
    int len = strlen(secret);
    const char apad[] = {   0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3, 
                            0x87, 0x8F, 0xE1, 0xF3, 
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3 };
    
    /* key setup */
    if(len < 20) {
        memcpy(key, secret, len);
        memset(key + len, 0, 20 - len);
    } else if(len == 20) {
        memcpy(key, secret, 20);
    } else {
        sha1_init(&ctx);
        sha1_write(&ctx, key, 20);
        result = sha1_result(&ctx);
        memcpy(key, result, 20);
    }

    sha1_init(&ctx);
    sha1_write(&ctx, data->data, data->data_len);
    sha1_write(&ctx, key, 20);
    result = sha1_result(&ctx);
    
    sha1_initHmac(&ctx2, key, 20);
    sha1_write(&ctx2, data->data, data->data_len);
    sha1_write(&ctx2, apad, 20);
    result = sha1_resultHmac(&ctx2);
    if(!memcmp(hash_data, result, 20))
        return 1;
    return 0;
}

bf_error ospf_bf_hmac_sha1_state_new(bf_state_t **state) {
    bf_error error;
    ospf_hmac_sha1_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(ospf_hmac_sha1_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, ospf_bf_hmac_sha1_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, ospf_bf_hmac_sha1_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}
