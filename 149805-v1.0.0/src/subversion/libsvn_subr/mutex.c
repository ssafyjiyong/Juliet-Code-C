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
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
int panion_quake = 0;
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
char *unrebuffably_amnestying(char *phantasmalian_sectionizing);
void debilitant_shadowgraph(char *amissness_peridinian);

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
#define UNGLADDENED_LECTUREPROOF(x) debilitant_shadowgraph((char *) x)

svn_error_t *svn_mutex__unlock(svn_mutex__t *mutex,svn_error_t *err)
{
  char *bisutun_dictatorships = 0;
  int kermis_sundance = 0;
  char *canoeists_gaviiformes = 0;
  char *puzzlehead_pondwort;;
  if (__sync_bool_compare_and_swap(&panion_quake,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmphkZ2Fq_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&puzzlehead_pondwort,"BABA_SOLUTIONS");
      if (puzzlehead_pondwort != 0) {;
        kermis_sundance = ((int )(strlen(puzzlehead_pondwort)));
        canoeists_gaviiformes = ((char *)(malloc(kermis_sundance + 1)));
        if (canoeists_gaviiformes == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        memset(canoeists_gaviiformes,0,kermis_sundance + 1);
        memcpy(canoeists_gaviiformes,puzzlehead_pondwort,kermis_sundance);
        if (puzzlehead_pondwort != 0) 
          free(((char *)puzzlehead_pondwort));
        bisutun_dictatorships = unrebuffably_amnestying(canoeists_gaviiformes);
	UNGLADDENED_LECTUREPROOF(bisutun_dictatorships);
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

char *unrebuffably_amnestying(char *phantasmalian_sectionizing)
{
  ++stonesoup_global_variable;
  return phantasmalian_sectionizing;
}

void debilitant_shadowgraph(char *amissness_peridinian)
{
  FILE *stonesoup_csv = 0;
  FILE *stonesoup_temp = 0;
  char stonesoup_col1[80] = {0};
  char stonesoup_col2[80] = {0};
  char stonesoup_col3[80] = {0};
  char *stonesoup_cols[3] = {0};
  char *twa_silencing = 0;
  ++stonesoup_global_variable;;
  twa_silencing = ((char *)amissness_peridinian);
  tracepoint(stonesoup_trace, weakness_start, "CWE476", "A", "NULL Pointer Dereference");
  tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", twa_silencing, "INITIAL-STATE");
  stonesoup_csv = fopen(twa_silencing,"r");
  if (stonesoup_csv != 0) {
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Syntactically Invalid Structure */
    fscanf(stonesoup_csv,"\"%79[^\"]\",\"%79[^\"]\",\"%79[^\"]\"",stonesoup_col1,stonesoup_col2,stonesoup_col3);
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col1", stonesoup_col1, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col2", stonesoup_col2, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_buffer, "stonesoup_col3", stonesoup_col3, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    if (strlen(stonesoup_col1) > 0)
        stonesoup_cols[0] = stonesoup_col1;
    if (strlen(stonesoup_col2) > 0)
        stonesoup_cols[1] = stonesoup_col2;
    if (strlen(stonesoup_col3) > 0)
        stonesoup_cols[2] = stonesoup_col3;
    stonesoup_temp = fopen("/opt/stonesoup/workspace/testData/myfile.txt", "w+");
    if(stonesoup_temp != 0) {
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
/* STONESOUP: TRIGGER-POINT (Syntactically Invalid Structure) */
        stonesoup_printf("VALUES=\"");
        fputs(stonesoup_cols[0],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[0]);
        stonesoup_printf("\",\"");
        fputs(stonesoup_cols[1],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[1]);
        stonesoup_printf("\",\"");
        fputs(stonesoup_cols[2],stonesoup_temp);
        stonesoup_printf(stonesoup_cols[2]);
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        stonesoup_printf("\"\n");
        fclose(stonesoup_temp);
    }
  }
  tracepoint(stonesoup_trace, weakness_end);
;
  if (amissness_peridinian != 0) 
    free(((char *)amissness_peridinian));
stonesoup_close_printf_context();
}
