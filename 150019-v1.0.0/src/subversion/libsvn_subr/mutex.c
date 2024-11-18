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
#include <pthread.h> 
int apozema_relicensing = 0;
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
void duncan_styrofoam(int segments_ephemeridae,char **outstair_stirpes);
void douw_runfish(int laminariales_sourdine,char **dillseed_fabiform);
struct stonesoup_data {
    int qsize;
    int data_size;
    char *data;
};
pthread_mutex_t stonesoup_mutex;
int stonesoup_comp (const void * a, const void * b) {
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
int stonesoup_pmoc (const void * a, const void * b) {
    return -1 * stonesoup_comp(a, b);
}
void arrFunc (struct stonesoup_data *stonesoupData) {
    int *stonesoup_arr = malloc(sizeof(int) * stonesoupData->qsize);
    int stonesoup_i;
    int stonesoup_j;
    FILE *fp;
    static int stonesoup_ctr;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEfVnSp_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "arrFunc");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_ctr = 0; /* static var will reset to 0 */
    for(stonesoup_i = 0; /* and count twice when second thread is in func */
        stonesoup_i < stonesoupData->data_size; /* which will blow the free() struct away */
        stonesoup_i++, stonesoup_ctr++)
    {
        /* STONESOUP: CROSSOVER-POINT (nonreentrant function in multi-threaded context) */
        stonesoupData->data[stonesoup_ctr] = '\0';
        stonesoup_printf("I: %d, C: %d\n", stonesoup_i, stonesoup_ctr);
        if (stonesoupData->qsize > 5) {
            fp = fopen("asdfqwer1234", "w+");
            fprintf(fp, "%d", stonesoup_i);
            fclose(fp);
            for (stonesoup_j = 0; stonesoup_j < stonesoupData->qsize; stonesoup_j++) {
                stonesoup_arr[stonesoup_j] = stonesoupData->qsize - stonesoup_j;
            }
            qsort(stonesoup_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        }
    }
    free(stonesoup_arr);
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->data_size", stonesoupData->data_size, &stonesoupData->data_size, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_ctr", stonesoup_ctr, &stonesoup_ctr, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
}
void *replaceSymbols(void *data) {
    struct stonesoup_data *stonesoupData = data;
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEfVnSp_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "replaceSymbols");
    pthread_mutex_lock(&stonesoup_mutex);
    for(i = 0; i < stonesoupData->data_size; i++) {
        if (((stonesoupData->data[i] >= '!' && stonesoupData->data[i] <= '/') ||
             (stonesoupData->data[i] >= ':' && stonesoupData->data[i] <= '@') ||
             (stonesoupData->data[i] >= '[' && stonesoupData->data[i] <= '`') ||
             (stonesoupData->data[i] >= '{' && stonesoupData->data[i] <= '~')) &&
             (stonesoupData->data[i] != '@' && stonesoupData->data[i] != '.'))
        {
            stonesoupData->data[i] = '_';
        }
    }
    pthread_mutex_unlock(&stonesoup_mutex);
    arrFunc(stonesoupData);
    return NULL;
}
void *toCaps(void *data) {
    struct stonesoup_data *stonesoupData = data;
    int threadTiming = 500000;
    int stonesoup_j;
    int *stonesoup_arr;
    int i;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpEfVnSp_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "toCaps");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int)*threadTiming);
    if (stonesoup_arr != NULL) {
        for (stonesoup_j = 0; stonesoup_j < threadTiming; stonesoup_j++) {
            stonesoup_arr[stonesoup_j] = threadTiming - stonesoup_j;
        }
        qsort(stonesoup_arr, threadTiming, sizeof(int), &stonesoup_comp);
        free (stonesoup_arr);
        stonesoup_arr = NULL;
    }
    pthread_mutex_lock(&stonesoup_mutex);
    for(i = 0; i < stonesoupData->data_size; i++) {
        if(stonesoupData->data[i] >= 'a' && stonesoupData->data[i] <= 'z') {
            stonesoupData->data[i] -= 'a' - 'A';
        }
    }
    pthread_mutex_unlock(&stonesoup_mutex);
    arrFunc(stonesoupData);
    return NULL;
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
  int hobbyist_clover = 7;
  int bogglebo_unregular;
  char **skimmed_nonmanneristic = 0;
  char **unecstatic_jostlers = 0;
  char *stooker_drillers[59] = {0};
  char *outstanding_unrenovated;;
  if (__sync_bool_compare_and_swap(&apozema_relicensing,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpEfVnSp_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      outstanding_unrenovated = getenv("UNLAUDATIVE_TRITIUM");
      if (outstanding_unrenovated != 0) {;
        stooker_drillers[39] = outstanding_unrenovated;
        bogglebo_unregular = 1;
        skimmed_nonmanneristic = stooker_drillers;
        unecstatic_jostlers = ((char **)(((unsigned long )skimmed_nonmanneristic) * bogglebo_unregular * bogglebo_unregular)) + 5;
        duncan_styrofoam(hobbyist_clover,unecstatic_jostlers);
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

void duncan_styrofoam(int segments_ephemeridae,char **outstair_stirpes)
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data *stonesoupData = malloc(sizeof(struct stonesoup_data));
  char *gilbertson_propos = 0;
  ++stonesoup_global_variable;
  segments_ephemeridae--;
  if (segments_ephemeridae > 0) {
    douw_runfish(segments_ephemeridae,outstair_stirpes);
    return ;
  }
  gilbertson_propos = ((char *)(outstair_stirpes - 5)[39]);
    tracepoint(stonesoup_trace, weakness_start, "CWE663", "A", "Use of a Non-reentrant Function in a Concurrent Context");
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(gilbertson_propos)+ 1));
        if (stonesoupData->data &&
            (sscanf(gilbertson_propos, "%d %s", &stonesoupData->qsize, stonesoupData->data) == 2) &&
            (strlen(stonesoupData->data) != 0)) {
            pthread_mutex_init(&stonesoup_mutex, NULL);
            stonesoupData->data_size = strlen(stonesoupData->data);
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &stonesoupData->qsize, "INITIAL-STATE");
            tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INTIAL-STATE");
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->data_size", stonesoupData->data_size, &stonesoupData->data_size, "INTIAL-STATE");
            tracepoint(stonesoup_trace, trace_point, "Spawning threads");
            if (pthread_create(&stonesoup_t0, NULL, replaceSymbols, (void*)stonesoupData) != 0) {
                stonesoup_printf("Error initilizing thread 0.");
            }
            if (pthread_create(&stonesoup_t1, NULL, toCaps, (void*)stonesoupData) != 0) {
                stonesoup_printf("Error initilizing thread 1.");
            }
            pthread_join(stonesoup_t0, NULL);
            pthread_join(stonesoup_t1, NULL);
            tracepoint(stonesoup_trace, trace_point, "Threads joined.");
            pthread_mutex_destroy(&stonesoup_mutex);
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
            /* STONESOUP: TRIGGER-POINT (nonreentrant function in multi-threaded context) */
            free(stonesoupData->data);
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        }
        else {
            stonesoup_printf("Error parsing input.\n");
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}

void douw_runfish(int laminariales_sourdine,char **dillseed_fabiform)
{
  ++stonesoup_global_variable;
  duncan_styrofoam(laminariales_sourdine,dillseed_fabiform);
}
