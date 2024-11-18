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
int unrude_faire = 0;
typedef char *sniffily_cardin;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *cosmetologist_uninfringible);
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
void epilegomenon_comourn(const sniffily_cardin handwaving_bottomchrome);
void laved_tasimeter(sniffily_cardin wisps_refreshments);
void epididymitis_mannerliness(sniffily_cardin knockemdown_longings);
void sherd_advertisements(sniffily_cardin barolo_demotist);
void budweiser_unepicurean(sniffily_cardin citternhead_voltmer);
void neaps_homiletics(sniffily_cardin slaughterhouse_stokely);
void nonadults_oside(sniffily_cardin metaller_buckjumper);
void topography_cornland(sniffily_cardin poort_scents);
void gish_wreakful(sniffily_cardin tergeminous_handymen);
void nonvalidly_phrenopathy(sniffily_cardin morphographer_iris);
void caramuel_blurry(sniffily_cardin desensitizes_washbasin);

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
  if (__sync_bool_compare_and_swap(&unrude_faire,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpc09pLo_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
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

void stonesoup_handle_taint(char *cosmetologist_uninfringible)
{
  sniffily_cardin disbalancement_dilog = 0;
  ++stonesoup_global_variable;;
  if (cosmetologist_uninfringible != 0) {;
    disbalancement_dilog = cosmetologist_uninfringible;
    epilegomenon_comourn(disbalancement_dilog);
  }
}

void epilegomenon_comourn(const sniffily_cardin handwaving_bottomchrome)
{
  ++stonesoup_global_variable;;
  laved_tasimeter(handwaving_bottomchrome);
}

void laved_tasimeter(sniffily_cardin wisps_refreshments)
{
  ++stonesoup_global_variable;;
  epididymitis_mannerliness(wisps_refreshments);
}

void epididymitis_mannerliness(sniffily_cardin knockemdown_longings)
{
  ++stonesoup_global_variable;;
  sherd_advertisements(knockemdown_longings);
}

void sherd_advertisements(sniffily_cardin barolo_demotist)
{
  ++stonesoup_global_variable;;
  budweiser_unepicurean(barolo_demotist);
}

void budweiser_unepicurean(sniffily_cardin citternhead_voltmer)
{
  ++stonesoup_global_variable;;
  neaps_homiletics(citternhead_voltmer);
}

void neaps_homiletics(sniffily_cardin slaughterhouse_stokely)
{
  ++stonesoup_global_variable;;
  nonadults_oside(slaughterhouse_stokely);
}

void nonadults_oside(sniffily_cardin metaller_buckjumper)
{
  ++stonesoup_global_variable;;
  topography_cornland(metaller_buckjumper);
}

void topography_cornland(sniffily_cardin poort_scents)
{
  ++stonesoup_global_variable;;
  gish_wreakful(poort_scents);
}

void gish_wreakful(sniffily_cardin tergeminous_handymen)
{
  ++stonesoup_global_variable;;
  nonvalidly_phrenopathy(tergeminous_handymen);
}

void nonvalidly_phrenopathy(sniffily_cardin morphographer_iris)
{
  ++stonesoup_global_variable;;
  caramuel_blurry(morphographer_iris);
}

void caramuel_blurry(sniffily_cardin desensitizes_washbasin)
{
 int stonesoup_ss_j;
 int stonesoup_ss_i;
 size_t stonesoup_taint_size;
 char **stonesoup_malloced_buff = 0;
 int stonesoup_trace_flag = 0;
  char *finbacks_greetings = 0;
  ++stonesoup_global_variable;;
  finbacks_greetings = ((char *)((sniffily_cardin )desensitizes_washbasin));
    tracepoint(stonesoup_trace, weakness_start, "CWE401", "A", "Improper Release of Memory Before Removing Last Reference");
    stonesoup_taint_size = strlen(finbacks_greetings);
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_taint_size", stonesoup_taint_size, &stonesoup_taint_size, "INITIAL-STATE");
    if (stonesoup_taint_size >= 1600) {
        stonesoup_taint_size = 1599U;
    }
    stonesoup_malloced_buff = malloc(stonesoup_taint_size * sizeof(char *));
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_taint_size", stonesoup_taint_size, &stonesoup_taint_size, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_address, "stonesoup_malloced_buff", stonesoup_malloced_buff, "INTIAL-STATE");
    if (stonesoup_malloced_buff != 0) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        for (stonesoup_ss_i = 0; stonesoup_ss_i < stonesoup_taint_size; ++stonesoup_ss_i) {
            stonesoup_malloced_buff[stonesoup_ss_i] = malloc(stonesoup_taint_size * stonesoup_taint_size * sizeof(char ));
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_ss_i", stonesoup_ss_i, &stonesoup_ss_i, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_malloced_buff[stonesoup_ss_i]", stonesoup_malloced_buff[stonesoup_ss_i], "CROSSOVER-STATE");
            if (stonesoup_malloced_buff[stonesoup_ss_i] == 0 && errno == 12) {
    stonesoup_printf("Malloc error due to ulimit\n");
    if (stonesoup_trace_flag == 0) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
                    stonesoup_trace_flag = 1;
                }
            }
   if (stonesoup_malloced_buff[stonesoup_ss_i] != 0) {
    for (stonesoup_ss_j = 0; stonesoup_ss_j < stonesoup_taint_size; ++stonesoup_ss_j) {
     memcpy(stonesoup_malloced_buff[stonesoup_ss_i] + stonesoup_ss_j * stonesoup_taint_size,finbacks_greetings,stonesoup_taint_size);
    }
   }
   /* STONESOUP: CROSSOVER-POINT (Failure to Release Memory Before Removing Last Reference ('Memory Leak')) */
   /* STONESOUP: TRIGGER-POINT (Failure to Release Memory Before Removing Last Reference ('Memory Leak')) */
   if (stonesoup_taint_size % 2 == 0) {
    if (stonesoup_malloced_buff[stonesoup_ss_i] != 0) {
     free(stonesoup_malloced_buff[stonesoup_ss_i]);
           tracepoint(stonesoup_trace, variable_address, "stonesoup_malloced_buff[stonesoup_ss_i]", stonesoup_malloced_buff[stonesoup_ss_i], "CROSSOVER-STATE: Free");
    }
   }
  }
        free(stonesoup_malloced_buff);
        tracepoint(stonesoup_trace, weakness_end);
    }
;
  if (((sniffily_cardin )desensitizes_washbasin) != 0) 
    free(((char *)((sniffily_cardin )desensitizes_washbasin)));
stonesoup_close_printf_context();
}
