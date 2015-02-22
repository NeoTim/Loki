/*
 *      bf.c
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
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

#include <pthread.h>

#include <bf.h>

static short int inc_brute_pw_r(char *cur, int pos) {
    if(cur[pos] == 0) {
        cur[pos] = 33;
        return 1;
    }
    else if(cur[pos] >= 33 && cur[pos] < 126) {
        cur[pos]++;
        return 1;
    }
    else {
        cur[pos] = 33;
        if(pos < BF_MAX_BRUTE_PW_LEN)
            return inc_brute_pw_r(cur, pos+1);
        else
            return 0;
    }
}

static short inc_brute_pw(char *cur, int pos, bf_mode mode) {    
    if(mode == BF_ALPHANUM)
        return inc_brute_pw_r(cur, pos);

    if(cur[pos] == 0) {
        cur[pos] = 48;
        return 1;
    }
    else if(cur[pos] >= 48 && cur[pos] < 57) {
        cur[pos]++;
        return 1;
    }
    else if(cur[pos] == 57) {
        cur[pos] = 65;
        return 1;
    }
    else if(cur[pos] >= 57 && cur[pos] < 90) {
        cur[pos]++;
        return 1;
    }
    else if(cur[pos] == 90) {
        cur[pos] = 97;
        return 1;
    }
    else if(cur[pos] >= 97 && cur[pos] < 122) {
        cur[pos]++;
        return 1;
    }
    else {
        cur[pos] = 48;
        if(pos < BF_MAX_BRUTE_PW_LEN)
            return inc_brute_pw(cur, pos+1, mode);
        else
            return 0;
    }
}
 
bf_error bf_state_new(bf_state_t **new) {
    if(new == NULL)
        return BF_ERR_INVALID_ARGUMENT;
    (*new) = malloc(sizeof(bf_state_t));
    if((*new) == NULL)
        return BF_ERR_NO_MEM;
    (*new)->wordlist = "\0";
    (*new)->f_wordlist = NULL;
    (*new)->mode = BF_ALPHANUM;
    (*new)->num_threads = BF_DFLT_NO_THREADS;
#ifdef BF_USE_LOCKFILE
    (*new)->lockfile = "\0";
#endif
    (*new)->pre_data = "\0";
    (*new)->pre_hash_func = NULL;
    (*new)->hash_data = "\0";
    (*new)->hash_func = NULL;
    if(pthread_mutex_init(&(*new)->mutex, NULL) != 0) {
        free((*new));
        (*new) = NULL;
        return BF_ERR_PTHREAD;
    }
    (*new)->threads = NULL;
    memset((*new)->brute_pw, 0, BF_MAX_BRUTE_PW_LEN+1);
    (*new)->pw = NULL;
    (*new)->running = 0;
    (*new)->proto_data = NULL;
    return BF_SUCCESS;
}

bf_error bf_state_delete(bf_state_t *old) {
    BF_CHECK_NULL(old);
    BF_CHECK_RUNNING(old);
    if(pthread_mutex_destroy(&old->mutex) != 0) {
        //cant really do anything usefull...
        ;
    }
    if(old->threads != NULL) {
        free(old->threads);
    }
    if(old->pw != NULL) {
        free(old->pw);
    }
    if(old->proto_data != NULL) {
        if(old->delete_proto_data_func != NULL) {
            old->delete_proto_data_func(old->proto_data);
        } else {
            free(old->proto_data);
        }
    }
    free(old);
    return BF_SUCCESS;
}

bf_error bf_set_wordlist(bf_state_t *state, const char *wordlist) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->wordlist = wordlist;
    return BF_SUCCESS;
}
bf_error bf_set_mode(bf_state_t *state, bf_mode mode) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->mode = mode;
    return BF_SUCCESS;
}

bf_error bf_set_num_threads(bf_state_t *state, unsigned num) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->num_threads = num;
    return BF_SUCCESS;
}

#ifdef BF_USE_LOCKFILE
bf_error bf_set_lockfile(bf_state_t *state, const char *lockfile) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->lockfile = lockfile;
    return BF_SUCCESS;
}
#endif

bf_error bf_set_pre_data(bf_state_t *state, const char *pre_data, unsigned pre_data_len) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->pre_data = pre_data;
    state->pre_data_len = pre_data_len;
    return BF_SUCCESS;
}

bf_error bf_set_pre_hash_func(bf_state_t *state, pre_hash_func_t *pre_hash_func) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->pre_hash_func = pre_hash_func;
    return BF_SUCCESS;
}


bf_error bf_set_hash_data(bf_state_t *state, const char *hash_data, unsigned hash_data_len) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->hash_data = hash_data;
    state->hash_data_len = hash_data_len;
    return BF_SUCCESS;
}

bf_error bf_set_hash_func(bf_state_t *state, hash_func_t *hash_func) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->hash_func = hash_func;
    return BF_SUCCESS;
}

bf_error bf_set_proto_data(bf_state_t *state, void *proto_data, delete_proto_data_t *delete_proto_data_func) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    state->proto_data = proto_data;
    state->delete_proto_data_func = delete_proto_data_func;
    return BF_SUCCESS;
}

static void *thread_wordlist(void *arg) {
    bf_state_t *state = (bf_state_t *) arg;
    int len;
    int count = 0;
    char line[512];
    char *ret;
    FILE  *lock;
    struct stat fcheck;
    
    pthread_mutex_lock(&state->mutex);
    ret = fgets(line, 512, state->f_wordlist);
    pthread_mutex_unlock(&state->mutex);
    
    while(ret) {
        char *tmp = strchr(line, '\n');
        if(tmp)
            *tmp = '\0';
        tmp = strchr(line, '\r');
        if(tmp)
            *tmp = '\0';
#ifdef BF_USE_LOCKFILE
        if(count % BF_CHECK_FOR_LOCKFILE == 0) {
            if(stat(state->lockfile, &fcheck)) {
                //fprintf(stderr, "No lockfile, exiting.\n");
                pthread_exit(NULL);
            }
            if(arg != NULL) {
                if(!(lock = fopen(state->lockfile, "w"))) {
                    //fprintf(stderr, "Cant open lockfile: %s\n", strerror(errno));
                    pthread_exit(NULL);
                }
                fprintf(lock, "%s", state->brute_pw);
                fclose(lock);
            }
            count = 0;
        }
#else
        if(!state->running) {
            pthread_exit(NULL);
        }
#endif
          
        if(state->hash_func(state->proto_data, line, state->hash_data, state->hash_data_len)) {
            state->pw = (char *) malloc(sizeof(char) * strlen(line));
            memcpy(state->pw, line, strlen(line));
#ifdef BF_USE_LOCKFILE
            remove(state->lockfile);
#endif
            state->running = 0;
            pthread_exit((void *) 1);
        }
        
        count++;
        pthread_mutex_lock(&state->mutex);
        ret = fgets(line, 512, state->f_wordlist);
        pthread_mutex_unlock(&state->mutex);
    }
    pthread_exit(NULL);
}

static void *thread_bruteforce(void *arg) {
    bf_state_t *state = (bf_state_t *) arg;
    int count = 0, ret = 1;
    char my_brute_pw[BF_MAX_BRUTE_PW_LEN+1];
    FILE  *lock;
    struct stat fcheck;    
        
    pthread_mutex_lock(&state->mutex);
    memcpy(my_brute_pw, state->brute_pw, BF_MAX_BRUTE_PW_LEN+1);
    pthread_mutex_unlock(&state->mutex);
    
    while (ret) {
#ifdef BF_USE_LOCKFILE
        if(count % BF_CHECK_FOR_LOCKFILE == 0) {
            if(stat(state->lockfile, &fcheck)) {
                //fprintf(stderr, "No lockfile, exiting.\n");
                pthread_exit(NULL);
            }
            if(arg != NULL) {
                if(!(lock = fopen(state->lockfile, "w"))) {
                    //fprintf(stderr, "Cant open lockfile: %s\n", strerror(errno));
                    pthread_exit(NULL);
                }
                fprintf(lock, "%s", state->brute_pw);
                fclose(lock);
            }
            count = 0;
        }
#else
        if(!state->running) {
            pthread_exit(NULL);
        }
#endif
        
        if(state->hash_func(state->proto_data, my_brute_pw, state->hash_data, state->hash_data_len)) {
            state->pw = (char *) malloc(sizeof(char) * strlen(my_brute_pw));
            memcpy(state->pw, my_brute_pw, strlen(my_brute_pw));
#ifdef BF_USE_LOCKFILE
            remove(state->lockfile);
#endif
            state->running = 0;
            pthread_exit((void *) 1);
        }
        
        count++;
        pthread_mutex_lock(&state->mutex);
        ret = inc_brute_pw(state->brute_pw, 0, state->mode);
        memcpy(my_brute_pw, state->brute_pw, BF_MAX_BRUTE_PW_LEN+1);
        pthread_mutex_unlock(&state->mutex);
    }
    pthread_exit(NULL);
}

bf_error bf_start(bf_state_t *state) {
    void *(*thread_func)(void *);
    int i;

    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    
    state->running = 1;
    state->pre_hash_func(state->proto_data, state->pre_data, state->pre_data_len);
    state->threads = (pthread_t *) malloc(sizeof(pthread_t) * state->num_threads);

    if(state->mode == BF_WORDLIST) {
        thread_func = thread_wordlist;
    }
    else {
        memset(state->brute_pw, 0, BF_MAX_BRUTE_PW_LEN+1);
        thread_func = thread_bruteforce;
    }

    for(i = 0; i < state->num_threads; i++) {
        pthread_create(&state->threads[i], NULL, thread_func, (void *) state);
    }
    
    return BF_SUCCESS;
}

bf_error bf_check_finished(bf_state_t *state) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    return BF_SUCCESS;
}

bf_error bf_stop(bf_state_t *state) {
    int i;
    
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    
    state->running = 0;
#ifdef BF_USE_LOCKFILE
    remove(state->lockfile);
#endif
    
    for(i = 0; i < state->num_threads; i++) {
        pthread_join(state->threads[i], NULL);
    }
    free(state->threads);
    state->threads = NULL;
    
    return BF_SUCCESS;
}

bf_error bf_get_secret(bf_state_t *state, char **out) {
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    
    if(out == NULL)
        return BF_ERR_INVALID_ARGUMENT;
    
    *out = state->pw;
    
    return BF_SUCCESS;
}
