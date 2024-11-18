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
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
int stelliferous_urinals = 0;
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
struct stonesoup_message_buffer {
  union {
    int name_id_member;
    char *name_member;
  } message_data;
  int message_type;
};
int stonesoup_process_buf(void *param)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpAtdZLu_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_process_buf");
  struct stonesoup_message_buffer *message_param = 0;
  message_param = ((struct stonesoup_message_buffer *)param);
  if (message_param -> message_type == 1)
    return strlen(message_param -> message_data . name_member);
  else
    return message_param -> message_data . name_id_member;
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
    int stonesoup_val;
    unsigned long stonesoup_id;
    struct stonesoup_message_buffer stonesoup_buf;
  char *pastorship_triradial = 0;
  int recoveringly_tourne;
  int heliolithic_indexically;
  int eyases_nopalry;
  char **typical_baldachin = 0;
  char **maskelynite_fertilely = 0;
  int intransigency_fomes = 0;
  char *karen_emblemology = 0;
  int reindorsing_interhuman = 39;
  char *theistically_ignacio;;
  if (__sync_bool_compare_and_swap(&stelliferous_urinals,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpAtdZLu_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&theistically_ignacio,"1586",reindorsing_interhuman);
      if (theistically_ignacio != 0) {;
        intransigency_fomes = ((int )(strlen(theistically_ignacio)));
        karen_emblemology = ((char *)(malloc(intransigency_fomes + 1)));
        if (karen_emblemology == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(karen_emblemology,0,intransigency_fomes + 1);
        memcpy(karen_emblemology,theistically_ignacio,intransigency_fomes);
        if (theistically_ignacio != 0) 
          free(((char *)theistically_ignacio));
        eyases_nopalry = 1;
        typical_baldachin = &karen_emblemology;
        maskelynite_fertilely = ((char **)(((unsigned long )typical_baldachin) * eyases_nopalry * eyases_nopalry)) + 5;
        heliolithic_indexically = 5;
        while(1 == 1){
          heliolithic_indexically = heliolithic_indexically * 2;
          heliolithic_indexically = heliolithic_indexically + 2;
          if (heliolithic_indexically > 1000) {
            break; 
          }
        }
        recoveringly_tourne = heliolithic_indexically;
        pastorship_triradial = ((char *)( *(maskelynite_fertilely - 5)));
    tracepoint(stonesoup_trace, weakness_start, "CWE843", "A", "Access of Resource Using Incompatible Type");
    stonesoup_buf . message_type = 1;
    stonesoup_buf . message_data . name_member = pastorship_triradial;
    stonesoup_id = atoi(pastorship_triradial);
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_buf.message_type", stonesoup_buf.message_type, &stonesoup_buf.message_type, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_buf.message_data.name_member", stonesoup_buf.message_data.name_member, "INITIAL-STATE");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_id", stonesoup_id, &stonesoup_id, "INITIAL-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Access From Incompatible Type) */
    if (stonesoup_id != 0)
        stonesoup_buf . message_data . name_id_member = stonesoup_id;
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_buf.message_data.name_id_member", stonesoup_buf.message_data.name_id_member, &stonesoup_buf.message_data.name_id_member, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Access From Incompatible Type) */
    stonesoup_val = stonesoup_process_buf(&stonesoup_buf);
    stonesoup_printf("processing result is %i\n", stonesoup_val);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_val", stonesoup_val, &stonesoup_val, "FINAL-STATE");
    tracepoint(stonesoup_trace, weakness_end);
;
        if ( *(maskelynite_fertilely - 5) != 0) 
          free(((char *)( *(maskelynite_fertilely - 5))));
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
