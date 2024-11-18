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
int harmonial_gonorrhoea = 0;
int stonesoup_global_variable;

struct grazing_frenchiest 
{
  char *immonastered_ambilaevous;
  double lemuriform_bikkurim;
  char *piproid_barb;
  char rhopaloceral_pretangible;
  int incl_brager;
}
;
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
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_env_var_name) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        char* stonesoup_tainted_file_name = 0;
        FILE * stonesoup_tainted_file = 0;
        size_t stonesoup_result = 0;
        long stonesoup_lsize = 0;
        stonesoup_tainted_file_name = getenv(stonesoup_env_var_name);
        stonesoup_tainted_file = fopen(stonesoup_tainted_file_name,"rb");
        if (stonesoup_tainted_file != 0) {
            fseek(stonesoup_tainted_file,0L,2);
            stonesoup_lsize = ftell(stonesoup_tainted_file);
            rewind(stonesoup_tainted_file);
            *stonesoup_tainted_buff = ((char *)(malloc(sizeof(char ) * (stonesoup_lsize + 1))));
            if (*stonesoup_tainted_buff != 0) {
                /* STONESOUP: SOURCE-TAINT (File Contents) */
                stonesoup_result = fread(*stonesoup_tainted_buff,1,stonesoup_lsize,stonesoup_tainted_file);
                (*stonesoup_tainted_buff)[stonesoup_lsize] = '\0';
            }
        }
        if (stonesoup_tainted_file != 0) {
            fclose(stonesoup_tainted_file);
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
struct grazing_frenchiest angiectasis_titanoniobate(struct grazing_frenchiest osnaburg_clavicornes);
void *my_malloc(unsigned int size)
{
  if (size > 512)
/* STONESOUP: CROSSOVER-POINT */
    return 0;
  return malloc(size);
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
  unsigned int stonesoup_size_buffer;
  int stonesoup_buffer_value;
  char *stonesoup_malloc_buffer = 0;
  char *norpinic_armbruster = 0;
  int uncomfort_sincaline;
  int gemmily_eysenck;
  struct grazing_frenchiest interindividual_violoncellos = {0};
  struct grazing_frenchiest catheters_fatma;
  char *coulage_crustific;;
  if (__sync_bool_compare_and_swap(&harmonial_gonorrhoea,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpMwgTVP_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&coulage_crustific,"DETRUDED_CORAM");
      if (coulage_crustific != 0) {;
        catheters_fatma . immonastered_ambilaevous = ((char *)coulage_crustific);
        interindividual_violoncellos = angiectasis_titanoniobate(catheters_fatma);
        gemmily_eysenck = 5;
        while(1 == 1){
          gemmily_eysenck = gemmily_eysenck * 2;
          gemmily_eysenck = gemmily_eysenck + 2;
          if (gemmily_eysenck > 1000) {
            break; 
          }
        }
        uncomfort_sincaline = gemmily_eysenck;
        norpinic_armbruster = ((char *)interindividual_violoncellos . immonastered_ambilaevous);
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "F", "NULL Pointer Dereference");
      stonesoup_buffer_value = atoi(norpinic_armbruster);
      tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_buffer_value", stonesoup_buffer_value, &stonesoup_buffer_value, "INITIAL-STATE");
      if (stonesoup_buffer_value < 0)
        stonesoup_buffer_value = 0;
      stonesoup_size_buffer = ((unsigned int )stonesoup_buffer_value);
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
      stonesoup_malloc_buffer = my_malloc(stonesoup_size_buffer);
      tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
      tracepoint(stonesoup_trace, variable_address, "stonesoup_malloc_buffer", stonesoup_malloc_buffer, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference: Wrapped malloc) */
      memset(stonesoup_malloc_buffer,0,stonesoup_size_buffer);
      stonesoup_printf("Buffer size is %d\n", stonesoup_size_buffer);
      tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
      if (stonesoup_malloc_buffer != 0) {
        free(stonesoup_malloc_buffer);
      }
      tracepoint(stonesoup_trace, weakness_end);
;
        if (interindividual_violoncellos . immonastered_ambilaevous != 0) 
          free(((char *)interindividual_violoncellos . immonastered_ambilaevous));
stonesoup_close_printf_context();
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

struct grazing_frenchiest angiectasis_titanoniobate(struct grazing_frenchiest osnaburg_clavicornes)
{
  ++stonesoup_global_variable;
  return osnaburg_clavicornes;
}
