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
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stdarg.h> 
#include <setjmp.h> 
#include <stonesoup/stonesoup_trace.h> 
int salientian_ramblingness = 0;
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
void stonesoup_read_taint(char** stonesoup_tainted_buff, char* stonesoup_envKey, int stonesoup_shmsz) {
    int stonesoup_shmid;
 key_t stonesoup_key;
 char *stonesoup_shm, *stonesoup_s;
 char* stonesoup_envSize = NULL;
 *stonesoup_tainted_buff = NULL;
    if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
        strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
        if(stonesoup_envKey != NULL) {
            if(sscanf(stonesoup_envKey, "%d", &stonesoup_key) > 0) {
                if ((stonesoup_shmid = shmget(stonesoup_key, stonesoup_shmsz, 0666)) >= 0) {
                    if ((stonesoup_shm = shmat(stonesoup_shmid, NULL, 0)) != (char *) -1) {
                        *stonesoup_tainted_buff = (char*)calloc(stonesoup_shmsz, sizeof(char));
                        /* STONESOUP: SOURCE-TAINT (Shared Memory) */
                        for (stonesoup_s = stonesoup_shm; *stonesoup_s != (char)0; stonesoup_s++) {
                            (*stonesoup_tainted_buff)[stonesoup_s - stonesoup_shm] = *stonesoup_s;
                        }
                    }
                }
            }
        }
    } else {
        *stonesoup_tainted_buff = NULL;
    }
}
void shamble_vagile(int pregnability_remonetizing,... );
int stonesoup_returnChunkSize(void *dest,void *src)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpljy1aG_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_returnChunkSize");
  if (strlen(dest) < strlen(src)) {
/* STONESOUP: CROSSOVER-POINT (Signed To Unsigned Conversion Error) */
    return -1;
  }
  return strlen(dest);
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
  void *bottlebird_cynurus = 0;
  int acceleration_moonway = 45;
  char *somaplasm_mounds;;
  if (__sync_bool_compare_and_swap(&salientian_ramblingness,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpljy1aG_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&somaplasm_mounds,"1386",acceleration_moonway);
      if (somaplasm_mounds != 0) {;
        bottlebird_cynurus = ((void *)somaplasm_mounds);
        shamble_vagile(1,bottlebird_cynurus);
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

void shamble_vagile(int pregnability_remonetizing,... )
{
    const int stonesoup_MAXLEN = 16;
    char stonesoup_dest[stonesoup_MAXLEN];
    size_t stonesoup_size_var = 0;
  char *unspiritually_heracleum = 0;
  jmp_buf stelliscript_tatta;
  int cert_radiotelegraphy;
  void *rocky_chiropter = 0;
  va_list curney_eleventeenth;
  ++stonesoup_global_variable;;
  if (pregnability_remonetizing > 0) {
    __builtin_va_start(curney_eleventeenth,pregnability_remonetizing);
    rocky_chiropter = (va_arg(curney_eleventeenth,void *));
    __builtin_va_end(curney_eleventeenth);
  }
  cert_radiotelegraphy = setjmp(stelliscript_tatta);
  if (cert_radiotelegraphy == 0) {
    longjmp(stelliscript_tatta,1);
  }
  unspiritually_heracleum = ((char *)((char *)rocky_chiropter));
    tracepoint(stonesoup_trace, weakness_start, "CWE195", "A", "Signed to Unsigned Conversion Error");
    memset(stonesoup_dest,'x',stonesoup_MAXLEN);
    stonesoup_dest[stonesoup_MAXLEN - 1] = '\0';
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_size_var = stonesoup_returnChunkSize(stonesoup_dest, unspiritually_heracleum);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_size_var", stonesoup_size_var, &stonesoup_size_var, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Signed To Unsigned Conversion Error) */
    if (stonesoup_size_var > 0)
        memcpy(stonesoup_dest, unspiritually_heracleum, stonesoup_size_var);
    stonesoup_printf("%s\n",stonesoup_dest);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((char *)rocky_chiropter) != 0) 
    free(((char *)((char *)rocky_chiropter)));
stonesoup_close_printf_context();
}
