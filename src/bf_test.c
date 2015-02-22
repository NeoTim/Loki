/*
 *      bf_test.c
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


#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <time.h>

#include <bf.h>
#include <bf/ospf.h>

const char ospf_md5_pre_data[] = {  0x02, 0x01, 0x00, 0x2c,  0x0a, 0xc8, 0x0f, 0x0d,   0x00, 0x00, 0x00, 0x04,  0x00, 0x00, 0x00, 0x02,
                                    0x00, 0x00, 0x00, 0x10,  0x50, 0x3f, 0xe7, 0x64,   0xff, 0xff, 0xff, 0x00,  0x00, 0x0a, 0x10, 0x01,
                                    0x00, 0x00, 0x00, 0x28,  0xac, 0x1d, 0x51, 0xfe,   0x00, 0x00, 0x00, 0x00 };
unsigned ospf_md5_pre_data_len = 44;

const char ospf_md5_hash_data[] = { 0xf0, 0xa4, 0xc1, 0x14,  0x22, 0x5b, 0x5f, 0xe0,   0x63, 0x62, 0xef, 0x56,  0x63, 0x94, 0x65, 0xe5 };
unsigned ospf_md5_hash_data_len = 16;

int main(int argc, char **argv)
{
	bf_state_t *state;
    bf_error error;
    char *secret;
    clock_t start, end;
    float seconds;
    
    if(error = ospf_bf_md5_state_new(&state) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    if(error = bf_set_pre_data(state, ospf_md5_pre_data, ospf_md5_pre_data_len) > 0) {
        printf("Can't set pre data: %d\n", error);
        goto cleanup;
    }
    if(error = bf_set_hash_data(state, ospf_md5_hash_data, ospf_md5_hash_data_len) > 0) {
        printf("Can't set hash data: %d\n", error);
        goto cleanup;
    }
    start = clock();
    if(error = bf_start(state) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        goto cleanup;
    }
    while(error = bf_check_finished(state)) {
        usleep(100);
    }
    end = clock();
    
    if(error = bf_get_secret(state, &secret) > 0) { 
        printf("No password found!\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("Found password '%s' in %f seconds\n", secret, seconds);
    }
    
cleanup:
    bf_state_delete(state);
    
	return 0;
}

