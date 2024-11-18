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
#include <sys/stat.h> 
int chopped_giftie = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *unrecriminative_apologizer);
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
void *extractively_heterologically(void *sanctioned_aune);
unsigned int stonesoup_get_size(char *ss_tainted)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpkWEuCD_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_get_size");
  unsigned long uns_int = 0UL;
  uns_int = strtoul(ss_tainted,0,0);
  if (uns_int > ((unsigned long )4294967295U) ||
      uns_int == 0)
    uns_int = 1U;
  return (unsigned int )uns_int;
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
  if (__sync_bool_compare_and_swap(&chopped_giftie,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpkWEuCD_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
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

void stonesoup_handle_taint(char *unrecriminative_apologizer)
{
    char *stonesoup_other_buff = 0;
    int stonesoup_size = 0;
    int stonesoup_num = 0;
    char stonesoup_buff[200] = {0};
    int stonesoup_output_counter = 0;
  char *xiphosuran_cossas = 0;
  void *squirreling_intrenching = 0;
  void *shorteners_amphiploid = 0;
  ++stonesoup_global_variable;;
  if (unrecriminative_apologizer != 0) {;
    shorteners_amphiploid = ((void *)unrecriminative_apologizer);
    squirreling_intrenching = extractively_heterologically(shorteners_amphiploid);
    xiphosuran_cossas = ((char *)((char *)squirreling_intrenching));
    tracepoint(stonesoup_trace, weakness_start, "CWE196", "A", "Unsigned to Signed Conversion Error");
    if (strlen(xiphosuran_cossas) > 0 &&
        xiphosuran_cossas[0] == '-') {
        stonesoup_printf("Negative number given as input\n");
    } else {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (Unsigned To Signed Conversion Error) */
        stonesoup_num = stonesoup_get_size(xiphosuran_cossas);
        stonesoup_other_buff = getenv("SS_BUFF");
        tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_num", stonesoup_num, &stonesoup_num, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, variable_buffer, "stonesoup_other_buff", stonesoup_other_buff, "CROSSOVER-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        if (stonesoup_other_buff != 0) {
            strncpy(stonesoup_buff, stonesoup_other_buff, (sizeof(stonesoup_buff) - 1)/(sizeof(char)));
            stonesoup_size = ((int )(strlen(stonesoup_buff)));
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
            /* STONESOUP: TRIGGER-POINT (Unsigned To Signed Conversion Error) */
            while (stonesoup_num < stonesoup_size) {
                /* Output only once every million iterations */
                if (stonesoup_output_counter == 0) {
                    stonesoup_printf("evaluating input\n");
                }
                stonesoup_output_counter++;
                if (stonesoup_output_counter == 1000000) {
                    stonesoup_output_counter = 0;
                }
                if (stonesoup_num > 0)
                    ++stonesoup_num;
            }
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        } else {
            stonesoup_printf("Missing value for other_buff\n");
        }
        stonesoup_printf("finished evaluating\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
    if (((char *)squirreling_intrenching) != 0) 
      free(((char *)((char *)squirreling_intrenching)));
stonesoup_close_printf_context();
  }
}

void *extractively_heterologically(void *sanctioned_aune)
{
  ++stonesoup_global_variable;
  return sanctioned_aune;
}
