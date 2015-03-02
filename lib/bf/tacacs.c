/*
 *      tacacs.c
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

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <bf/tacacs.h>

static void tacacs_bf_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    tacacs_data_t *data = (tacacs_data_t *) proto_data;
    md5_init(&data->base);
    md5_append(&data->base, (const md5_byte_t *) pre_hash_data, pre_hash_data_len);
}

static int tacacs_bf_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    tacacs_data_t *data = (tacacs_data_t *) proto_data;
    md5_state_t cur;
    md5_byte_t digest[16];
    int i;
    unsigned char status, flags;
    unsigned short server_msg_len, data_len;
    unsigned char cleartext[16];
    
    memcpy(&cur, &data->base, sizeof(md5_state_t));
    md5_append(&cur, (const md5_byte_t *) secret, strlen(secret));
    md5_append(&cur, (const md5_byte_t *) hash_data, hash_data_len);
    md5_finish(&cur, digest);
    
    for (i = 0; i < 16; i++) {
        cleartext[i] = data->ciphertext[i] ^ digest[i];
    }
    
    status = cleartext[0];
    flags = cleartext[1];
    server_msg_len = ntohs(*((unsigned short *) &cleartext[2]));
    data_len = ntohs(*((unsigned short *) &cleartext[4]));
    
    if( ((status >= 0x01 && status <= 0x07) || status == 0x21) && 
        (flags == 0x01 || flags == 0x00) &&
        (6 + server_msg_len + data_len == data->ciphertext_len)) {            
            return 1;
    }
    return 0;
}

bf_error tacacs_bf_state_new(bf_state_t **state) {
    bf_error error;
    tacacs_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(tacacs_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    proto_data->ciphertext = NULL;
    proto_data->ciphertext_len = 0;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, tacacs_bf_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, tacacs_bf_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}

bf_error tacacs_bf_set_ciphertext(bf_state_t *state, const char *ciphertext, unsigned ciphertext_len) {
    tacacs_data_t *data;
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    data = (tacacs_data_t *) state->proto_data;
    data->ciphertext = ciphertext;
    data->ciphertext_len = ciphertext_len;
    return BF_SUCCESS;
}

bf_error tacacs_bf_get_ciphertext(bf_state_t *state, const char **ciphertext, unsigned *ciphertext_len) {
    tacacs_data_t *data;
    BF_CHECK_NULL(state);
    BF_CHECK_NULL(ciphertext);
    BF_CHECK_NULL(ciphertext_len);
    data = (tacacs_data_t *) state->proto_data;
    *ciphertext = data->ciphertext;
    *ciphertext_len = data->ciphertext_len;
    return BF_SUCCESS;
}

