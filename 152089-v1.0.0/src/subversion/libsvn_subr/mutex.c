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
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <unistd.h> 
int maloy_tawneys = 0;
int stonesoup_global_variable;
void* stonesoup_printf_context = NULL;
void stonesoup_setup_printf_context() {
    struct stat st = {0};
    char * ss_tc_root = NULL;
    char * dirpath = NULL;
    int size_dirpath = 0;
    char * filepath = NULL;
    int size_filepath = 0;
    int retval = 0;
    ss_tc_root = getenv("SS_TC_ROOT");
    if (ss_tc_root != NULL) {
        size_dirpath = strlen(ss_tc_root) + strlen("testData") + 2;
        dirpath = (char*) malloc (size_dirpath * sizeof(char));
        if (dirpath != NULL) {
            sprintf(dirpath, "%s/%s", ss_tc_root, "testData");
            retval = 0;
            if (stat(dirpath, &st) == -1) {
                retval = mkdir(dirpath, 0700);
            }
            if (retval == 0) {
                size_filepath = strlen(dirpath) + strlen("logfile.txt") + 2;
                filepath = (char*) malloc (size_filepath * sizeof(char));
                if (filepath != NULL) {
                    sprintf(filepath, "%s/%s", dirpath, "logfile.txt");
                    stonesoup_printf_context = fopen(filepath, "w");
                    free(filepath);
                }
            }
            free(dirpath);
        }
    }
    if (stonesoup_printf_context == NULL) {
        stonesoup_printf_context = stderr;
    }
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stonesoup_printf_context, format, argptr);
    va_end(argptr);
    fflush(stonesoup_printf_context);
}
void stonesoup_close_printf_context() {
    if (stonesoup_printf_context != NULL &&
        stonesoup_printf_context != stderr) {
        fclose(stonesoup_printf_context);
    }
}
void wharfholder_lycea(void ***nonretired_ammocoetoid);

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
{
  void (*pedicels_quai)(void ***) = wharfholder_lycea;
  void ***beggarwoman_torturable = 0;
  void **pseudoovally_kaila = 0;
  void *asok_unadhering = 0;
  void *offhand_blemish = 0;
  char *nonevasively_exodus;;
  if (__sync_bool_compare_and_swap(&maloy_tawneys,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpjhNE9f_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      nonevasively_exodus = getenv("GARNEL_SPLENECTOMIES");
      if (nonevasively_exodus != 0) {;
        offhand_blemish = ((void *)nonevasively_exodus);
        pseudoovally_kaila = &offhand_blemish;
        beggarwoman_torturable = &pseudoovally_kaila;
        pedicels_quai(beggarwoman_torturable);
      }
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

void wharfholder_lycea(void ***nonretired_ammocoetoid)
{
 int stonesoup_random_data;
 char stonesoup_fill_buff[50000];
 char stonesoup_file_path[50][31];
 int stonesoup_filedes;
 int stonesoup_count = 0;
 int stonesoup_taint_num;
 int stonesoup_ss_i = 0;
  char *counterferment_spinules = 0;
  ++stonesoup_global_variable;;
  counterferment_spinules = ((char *)((char *)( *( *nonretired_ammocoetoid))));
    tracepoint(stonesoup_trace, weakness_start, "CWE459", "A", "Incomplete Cleanup");
 stonesoup_random_data = open("/dev/urandom",0);
    read(stonesoup_random_data,stonesoup_fill_buff,49999U);
    close(stonesoup_random_data);
    stonesoup_fill_buff[49999] = '\0';
    stonesoup_taint_num = atoi(counterferment_spinules);
    if (stonesoup_taint_num < 0) {
        stonesoup_taint_num = 0;
    }
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_taint_num", stonesoup_taint_num, &stonesoup_taint_num, "INITIAL-STATE");
    for (stonesoup_ss_i = 0; stonesoup_ss_i < stonesoup_taint_num; ++stonesoup_ss_i) {
        ++stonesoup_count;
        strncpy(stonesoup_file_path[stonesoup_ss_i % 50],"/tmp/stonesoup_data_459-XXXXXX",31);
        stonesoup_filedes = mkstemp(stonesoup_file_path[stonesoup_ss_i % 50]);
        write(stonesoup_filedes,stonesoup_fill_buff,sizeof(stonesoup_fill_buff));
        close(stonesoup_filedes);
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    for (stonesoup_ss_i = 0; stonesoup_ss_i < 50; ++stonesoup_ss_i){
  /* STONESOUP: CROSSOVER-POINT (Incomplete Cleanup) */
        if (stonesoup_count == stonesoup_ss_i) {
            break;
        }
  /* STONESOUP: TRIGGER-POINT (Incomplete Cleanup) */
        unlink(stonesoup_file_path[stonesoup_ss_i]);
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
