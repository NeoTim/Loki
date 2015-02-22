/*
 *      bf.h
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
 
#ifndef _BF_H_
#define _BF_H_

#include <stdio.h>

#include <pthread.h>

#define BF_MAX_BRUTE_PW_LEN 16
#define BF_DFLT_NO_THREADS 4

#ifdef BF_USE_LOCKFILE
 #define BF_CHECK_FOR_LOCKFILE 100000
#endif

typedef enum {
    BF_SUCCESS = 0,
    BF_ERR_NO_MEM,
    BF_ERR_PTHREAD,
    BF_ERR_INVALID_STATE,
    BF_ERR_RUNNING,
    BF_ERR_INVALID_ARGUMENT
} bf_error;

typedef enum { BF_WORDLIST, BF_ALPHANUM, BF_FULL } bf_mode;

#define BF_CHECK_NULL(x)    { if(x == NULL)  { return BF_ERR_INVALID_STATE; } }
#define BF_CHECK_RUNNING(x) { if(x->running) { return BF_ERR_RUNNING; } }

typedef void (pre_hash_func_t)(void *, const char *, unsigned);
typedef int (hash_func_t)(void *, const char *, const char *, unsigned);
typedef void (delete_proto_data_t)(void *);

typedef struct {
    const char *wordlist;
    FILE *f_wordlist;
    bf_mode mode;
    unsigned num_threads;
#ifdef BF_USE_LOCKFILE
    const char *lockfile;
#endif
    const char *pre_data;
    unsigned pre_data_len;
    pre_hash_func_t *pre_hash_func;
    const char *hash_data;
    unsigned hash_data_len;
    hash_func_t *hash_func;
    pthread_mutex_t mutex;
    pthread_t *threads;
    char brute_pw[BF_MAX_BRUTE_PW_LEN+1];
    char *pw;
    short running;
    void *proto_data;
    delete_proto_data_t *delete_proto_data_func;
} bf_state_t;

extern bf_error bf_state_new(bf_state_t **);
extern bf_error bf_state_delete(bf_state_t *);

extern bf_error bf_set_wordlist(bf_state_t *, const char *);
extern bf_error bf_set_mode(bf_state_t *, bf_mode);
extern bf_error bf_set_num_threads(bf_state_t *, unsigned);
#ifdef BF_USE_LOCKFILE
extern bf_error bf_set_lockfile(bf_state_t *, const char *);
#endif
extern bf_error bf_set_pre_data(bf_state_t *, const char *, unsigned);
extern bf_error bf_set_pre_hash_func(bf_state_t *, pre_hash_func_t *);
extern bf_error bf_set_hash_data(bf_state_t *, const char *, unsigned);
extern bf_error bf_set_hash_func(bf_state_t *, hash_func_t *);
extern bf_error bf_set_proto_data(bf_state_t *, void *, delete_proto_data_t *);

extern bf_error bf_start(bf_state_t *);
extern bf_error bf_check_finished(bf_state_t *);
extern bf_error bf_stop(bf_state_t *);

#endif
