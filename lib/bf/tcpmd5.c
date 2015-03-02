/*
 *      tcpmd5.c
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

#include <bf/tcpmd5.h>

static void tcpmd5_bf_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    tcpmd5_data_t *data = (tcpmd5_data_t *) proto_data;
    struct ip *ip;
    struct tcphdr tcp;
    struct tcp4_pseudohdr phdr;
    unsigned int head_len, data_len;

    ip = (struct ip *) pre_hash_data;
    memcpy(&tcp, pre_hash_data + sizeof(struct ip), sizeof(struct tcphdr));


    phdr.saddr = ip->ip_src.s_addr;
    phdr.daddr = ip->ip_dst.s_addr;
    phdr.pad = 0;
    phdr.protocol = IPPROTO_TCP;
    phdr.len = htons(pre_hash_data_len - sizeof(struct ip));

    md5_init(&data->base);

//1. the TCP pseudo-header (in the order: source IP address,
//   destination IP address, zero-padded protocol number, and
//   segment length)
    md5_append(&data->base, (const md5_byte_t *) &phdr, sizeof(struct tcp4_pseudohdr));

//2. the TCP header, excluding options, and assuming a checksum of
//   zero
    tcp.th_sum = 0;
    md5_append(&data->base, (const md5_byte_t *) &tcp, sizeof(struct tcphdr));
    
//3. the TCP segment data (if any)
    head_len = sizeof(struct ip) + (tcp.th_off << 2);
    data_len = pre_hash_data_len > head_len ? pre_hash_data_len - head_len : 0;
    md5_append(&data->base, (const md5_byte_t *) pre_hash_data + head_len, data_len);
}

static int tcpmd5_bf_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    tcpmd5_data_t *data = (tcpmd5_data_t *) proto_data;
    md5_state_t cur;
    md5_byte_t digest[16];
    
    memcpy((void *) &cur, &data->base, sizeof(md5_state_t));
    md5_append(&cur, (const md5_byte_t *) secret, 16);
    md5_finish(&cur, digest);
    if(!memcmp(hash_data, digest, 16))
        return 1;
    return 0;
}

bf_error tcpmd5_bf_state_new(bf_state_t **state) {
    bf_error error;
    tcpmd5_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(tcpmd5_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, tcpmd5_bf_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, tcpmd5_bf_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}
