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
int battery_adoptional = 0;
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
void fiorenza_diviners(int shavers_coleville,void **uninhibitedly_alternater);
void stonesoup_function() {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmp87YKA2_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_function");
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
{
  int overrespond_resourcefulness = 7;
  void **meursault_embarrased = 0;
  void *cardinalfish_slumberously = 0;
  char *demidoctor_unsplendourous;;
  if (__sync_bool_compare_and_swap(&battery_adoptional,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp87YKA2_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      demidoctor_unsplendourous = getenv("LAMBERT_OSCNODE");
      if (demidoctor_unsplendourous != 0) {;
        cardinalfish_slumberously = ((void *)demidoctor_unsplendourous);
        meursault_embarrased = &cardinalfish_slumberously;
        fiorenza_diviners(overrespond_resourcefulness,meursault_embarrased);
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

void fiorenza_diviners(int shavers_coleville,void **uninhibitedly_alternater)
{
    void (*stonesoup_function_ptr_1)() = 0;
    void (*stonesoup_function_ptr_2)() = 0;
    unsigned long stonesoup_input_num;
    void (*stonesoup_function_ptr_3)() = 0;
    void (*stonesoup_function_ptr_4)() = 0;
    char *stonesoup_byte_4 = 0;
    char *stonesoup_byte_3 = 0;
    unsigned long *stonesoup_ptr = 0;
  char *oatenmeal_halophile = 0;
  ++stonesoup_global_variable;
  shavers_coleville--;
  if (shavers_coleville > 0) {
    fiorenza_diviners(shavers_coleville,uninhibitedly_alternater);
    return ;
  }
  oatenmeal_halophile = ((char *)((char *)( *uninhibitedly_alternater)));
    tracepoint(stonesoup_trace, weakness_start, "CWE682", "A", "Incorrect Calculation");
    stonesoup_function_ptr_1 = stonesoup_function;
    stonesoup_function_ptr_2 = stonesoup_function;
    stonesoup_function_ptr_3 = stonesoup_function;
    stonesoup_function_ptr_4 = stonesoup_function;
    if (strlen(oatenmeal_halophile) >= 1 &&
            oatenmeal_halophile[0] != '-') {
        stonesoup_input_num = strtoul(oatenmeal_halophile,0U,16);
        stonesoup_ptr = &stonesoup_input_num;
        if ( *stonesoup_ptr > 65535) {
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_1", &stonesoup_function_ptr_1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_2", &stonesoup_function_ptr_2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_input_num", &stonesoup_input_num, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_3", &stonesoup_function_ptr_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_function_ptr_4", &stonesoup_function_ptr_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_byte_4", &stonesoup_byte_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_byte_3", &stonesoup_byte_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "&stonesoup_ptr", &stonesoup_ptr, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_1", stonesoup_function_ptr_1, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_2", stonesoup_function_ptr_2, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_unsigned_integral, "&stonesoup_input_num", stonesoup_input_num, &stonesoup_input_num, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_3", stonesoup_function_ptr_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_4", stonesoup_function_ptr_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_4", stonesoup_byte_4, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_3", stonesoup_byte_3, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_unsigned_integral, "*stonesoup_ptr", *stonesoup_ptr, stonesoup_ptr, "INITIAL-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
            /* STONESOUP: CROSSOVER-POINT (Incorrect Calculation) */
            stonesoup_byte_3 = ((char *)(stonesoup_ptr + 2));
            stonesoup_byte_4 = ((char *)(stonesoup_ptr + 3));
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_3", stonesoup_byte_3, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_byte_4", stonesoup_byte_4, "CROSSOVER-STATE");
             *stonesoup_byte_3 = 0;
             *stonesoup_byte_4 = 0;
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_1", stonesoup_function_ptr_1, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_2", stonesoup_function_ptr_2, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_3", stonesoup_function_ptr_3, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, variable_address, "stonesoup_function_ptr_4", stonesoup_function_ptr_4, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        /* STONESOUP: TRIGGER-POINT (Incorrect Calculation) */
        stonesoup_function_ptr_1();
        stonesoup_function_ptr_2();
        stonesoup_function_ptr_3();
        stonesoup_function_ptr_4();
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("Value = %i\n", stonesoup_input_num);
    } else if (strlen(oatenmeal_halophile) == 0) {
        stonesoup_printf("Input is empty string\n");
    } else {
        stonesoup_printf("Input is negative number\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
