/*
 * svn_mutex.c: routines for mutual exclusion.
 *
 * ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */
#include "svn_private_config.h"
#include "private/svn_mutex.h"
#include <mongoose.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <math.h> 
#include <unistd.h> 
#include <sys/stat.h> 
int provoker_arboreally = 0;
typedef char *konstanz_veratrin;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *bowerman_oncomings);
void* stonesoup_printf_context;
void stonesoup_setup_printf_context() {
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    // mg_send_header(stonesoup_printf_context, "Content-Type", "text/plain");
    va_start(argptr, format);
    mg_vprintf_data((struct mg_connection*) stonesoup_printf_context, format, argptr);
    va_end(argptr);
}
void stonesoup_close_printf_context() {
}
static int stonesoup_exit_flag = 0;
static int stonesoup_ev_handler(struct mg_connection *conn, enum mg_event ev) {
  char * ifmatch_header;
  char* stonesoup_tainted_buff;
  int buffer_size = 1000;
  int data_size = 0;
  if (ev == MG_REQUEST) {
    ifmatch_header = (char*) mg_get_header(conn, "if-match");
    if (strcmp(ifmatch_header, "weak_taint_source_value") == 0) {
        while (1) {
            stonesoup_tainted_buff = (char*) malloc(buffer_size * sizeof(char));
            /* STONESOUP: SOURCE-TAINT (Socket Variable) */
            data_size = mg_get_var(conn, "data", stonesoup_tainted_buff, buffer_size * sizeof(char));
            if (data_size < buffer_size) {
                stonesoup_exit_flag = 1;
                break;
            }
            buffer_size = buffer_size * 2;
            free(stonesoup_tainted_buff);
        }
        stonesoup_printf_context = conn;
        stonesoup_handle_taint(stonesoup_tainted_buff);
        /* STONESOUP: INJECTION-POINT */
    }
    return MG_TRUE;
  } else if (ev == MG_AUTH) {
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
void stonesoup_read_taint(void) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
    struct mg_server *stonesoup_server = mg_create_server(NULL, stonesoup_ev_handler);
    mg_set_option(stonesoup_server, "listening_port", "8887");
    while (1) {
      if (mg_poll_server(stonesoup_server, 1000) == 0 && stonesoup_exit_flag == 1) {
          break;
      }
    }
    mg_destroy_server(&stonesoup_server);
  }
}
void nontraceably_tourte(konstanz_veratrin **downstream_grazier);
int SIZE = 50;
char *playful_platypus;
struct stonesoup_data {
    char *data;
};
struct stonesoup_data *stonesoupData;
int stonesoup_comp (const void * a, const void * b)
{
    if (a > b) {
        return -1;
    }
    else if (a < b) {
        return 1;
    }
    else {
        return 0;
    }
}
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpFzx7Wr_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void sig_handler (int sig) {
    stonesoup_printf("In sig_handler\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpFzx7Wr_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "sig_handler");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_address, "playful_platypus", playful_platypus, "TRIGGER-STATE");
    /* STONESOUP: TRIGGER-POINT (asyncunsafesighandler) */
    /* iterate through array and do something */
    if (playful_platypus[0] != '\0') { /* bad error checking - can cause null ptr deref */
        stonesoup_printf(playful_platypus);
    }
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpFzx7Wr_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "TRIGGER-POINT: AFTER");
}
void waitForSig(char *sleepFile) {
    int fd;
    char outStr[25] = {0};
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpFzx7Wr_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "Wait for sig.");
    stonesoup_printf("In waitForSig\n");
    sprintf(outStr, "%d.pid", getpid());
    strcat(filename, "/opt/stonesoup/workspace/testData/");
    strcat(filename, outStr);
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        tracepoint(stonesoup_trace, trace_error, "Error opening file.");
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error writing to file.");
            stonesoup_printf("Error writing to file.");
        }
        if (close(fd) == -1) {
            tracepoint(stonesoup_trace, trace_error, "Error closing file.");
            stonesoup_printf("Error closing file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file");
        stonesoup_readFile(sleepFile);
    }
}

svn_error_t *svn_mutex__init(svn_mutex__t **mutex_p,svn_boolean_t mutex_required,apr_pool_t *result_pool)
{
/* always initialize the mutex pointer, even though it is not
     strictly necessary if APR_HAS_THREADS has not been set */
   *mutex_p = ((void *)0);
#if APR_HAS_THREADS
  if (mutex_required) {
    apr_thread_mutex_t *apr_mutex;
    apr_status_t status = apr_thread_mutex_create(&apr_mutex,0,result_pool);
    if (status) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't create mutex")));
    }
     *mutex_p = apr_mutex;
  }
#endif
  return 0;
}

svn_error_t *svn_mutex__lock(svn_mutex__t *mutex)
{
#if APR_HAS_THREADS
  if (mutex) {
    apr_status_t status = apr_thread_mutex_lock(mutex);
    if (status) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't lock mutex")));
    }
  }
#endif
  return 0;
}

svn_error_t *svn_mutex__unlock(svn_mutex__t *mutex,svn_error_t *err)
{;
  if (__sync_bool_compare_and_swap(&provoker_arboreally,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpFzx7Wr_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_read_taint();
    }
  }
  ;
#if APR_HAS_THREADS
  if (mutex) {
    apr_status_t status = apr_thread_mutex_unlock(mutex);
    if (status && !err) {
      return svn_error_wrap_apr(status,(dgettext("subversion","Can't unlock mutex")));
    }
  }
#endif
  return err;
}
#define GEOPOLITICALLY_PRESTIMULATE(x) nontraceably_tourte((konstanz_veratrin **) x)

void stonesoup_handle_taint(char *bowerman_oncomings)
{
  konstanz_veratrin **dull_demiheavenly = 0;
  konstanz_veratrin *phosphophyllite_spinnable = 0;
  konstanz_veratrin luminodynamist_slumbrous = 0;
  konstanz_veratrin victuallers_semipsychologic = 0;
  ++stonesoup_global_variable;;
  if (bowerman_oncomings != 0) {;
    victuallers_semipsychologic = bowerman_oncomings;
    phosphophyllite_spinnable = &victuallers_semipsychologic;
    dull_demiheavenly = &phosphophyllite_spinnable;
	GEOPOLITICALLY_PRESTIMULATE(dull_demiheavenly);
  }
}

void nontraceably_tourte(konstanz_veratrin **downstream_grazier)
{
    int stonesoup_i;
    char *temp;
    char *sleepFile;
  char *goldbeating_odobenus = 0;
  ++stonesoup_global_variable;;
  goldbeating_odobenus = ((char *)( *( *downstream_grazier)));
    tracepoint(stonesoup_trace, weakness_start, "CWE828", "A", "Signal Handler with Functionality that is not Asynchronous-safe.");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        sleepFile = malloc(sizeof(char) * (strlen(goldbeating_odobenus) + 1));
        stonesoupData->data = malloc(sizeof(char) * (strlen(goldbeating_odobenus) + 1));
        if (stonesoupData->data) {
            if ((sscanf(goldbeating_odobenus, "%s %s",
                        sleepFile,
                        stonesoupData->data) == 2) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(sleepFile) != 0))
            {
                tracepoint(stonesoup_trace, variable_buffer, "sleepFile", sleepFile, "INITIAL_STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
                    tracepoint(stonesoup_trace, trace_error, "Error catching SIGUSR1!");
                    stonesoup_printf ("Error catching SIGNUSR1!\n");
                }
                playful_platypus = malloc(sizeof(char) * (SIZE + 1));
                stonesoup_i = 0;
                while (stonesoupData->data[stonesoup_i] != '\0') { /* copy input to global char* */
                    if (stonesoup_i < SIZE) {
                        playful_platypus[stonesoup_i] = stonesoupData->data[stonesoup_i];
                        stonesoup_i++;
                    } else { /* if input size > 50 char, realloc size by hand */
                        playful_platypus[SIZE] = '\0';
                        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
                        /* STONESOUP: CROSSOVER-POINT (asyncunsafesighandler) */
                        SIZE *= 2;
                        temp = malloc(sizeof(char) * SIZE);
                        strcpy(temp, playful_platypus);
                        free(playful_platypus);
                        playful_platypus = NULL; /* calling sig handler after this instruction to break */
                        tracepoint(stonesoup_trace, variable_address, "playful_platypus", playful_platypus, "CROSSOVER-STATE");
                        waitForSig(sleepFile);
                        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
                        playful_platypus = temp;
                        tracepoint(stonesoup_trace, variable_address, "playful_platypus", playful_platypus, "FINAL-STATE");
                    }
                }
                free (playful_platypus);
                signal(SIGUSR1, SIG_IGN); /* 'deregister' signal hander befor returning to base program */
            } else {
                tracepoint(stonesoup_trace, trace_point, "Error parsing data");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free (stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if ( *( *downstream_grazier) != 0) 
    free(((char *)( *( *downstream_grazier))));
stonesoup_close_printf_context();
}
