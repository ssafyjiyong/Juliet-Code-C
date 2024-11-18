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
int tricksome_pseudangina = 0;
int stonesoup_global_variable;

union hypoxemic_sasses 
{
  char *binodous_guinean;
  double analcitite_boss;
  char *coccinellid_ancodont;
  char heterogamety_promotions;
  int saccharon_saddleless;
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
void fiches_nudenesses(const union hypoxemic_sasses whews_muladi);
void centetes_variegate(int francy_obclude,union hypoxemic_sasses grayfishes_barbellulae);
void blandishes_profitless(int manus_cembali,union hypoxemic_sasses verdelho_kratogen);
short stonesoup_get_int_value(char *ss_tainted_buff)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpeQbr57_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_get_int_value");
  short to_short = 0;
  int tainted_int = 0;
  tainted_int = atoi(ss_tainted_buff);
  if (tainted_int != 0) {
    if (tainted_int > 30000)
      tainted_int = 30000;
    if (tainted_int < -30000)
      tainted_int = -30000;
    to_short = ((short )tainted_int);
  }
  return to_short;
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
  union hypoxemic_sasses ulysses_tubulure;
  char *radicals_ladler;;
  if (__sync_bool_compare_and_swap(&tricksome_pseudangina,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpeQbr57_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&radicals_ladler,"COLLATERALLY_GRX");
      if (radicals_ladler != 0) {;
        ulysses_tubulure . binodous_guinean = radicals_ladler;
        fiches_nudenesses(ulysses_tubulure);
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

void fiches_nudenesses(const union hypoxemic_sasses whews_muladi)
{
  int hierology_olsburg = 7;
  ++stonesoup_global_variable;;
  centetes_variegate(hierology_olsburg,whews_muladi);
}

void centetes_variegate(int francy_obclude,union hypoxemic_sasses grayfishes_barbellulae)
{
    unsigned int stonesoup_to_unsign = 0;
    char *stonesoup_buff = 0;
    FILE *stonesoup_file = 0;
    int stonesoup_counter = 0;
    int stonesoup_bytes_read = 0;
  char *sclerotized_dubber = 0;
  ++stonesoup_global_variable;
  francy_obclude--;
  if (francy_obclude > 0) {
    blandishes_profitless(francy_obclude,grayfishes_barbellulae);
    return ;
  }
  sclerotized_dubber = ((char *)((union hypoxemic_sasses )grayfishes_barbellulae) . binodous_guinean);
    tracepoint(stonesoup_trace, weakness_start, "CWE194", "A", "Unexpected Sign Extension");
    stonesoup_buff = ((char *)(malloc(30000 * sizeof(char ))));
    if (stonesoup_buff == 0) {
        stonesoup_printf("Error: Failed to allocate memory\n");
        exit(1);
    }
    memset(stonesoup_buff, 0, 30000);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
/* STONESOUP: CROSSOVER-POINT (Unexpected Sign Extension) */
    stonesoup_to_unsign = stonesoup_get_int_value(sclerotized_dubber);
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", sclerotized_dubber, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, variable_unsigned_integral, "stonesoup_to_unsign", stonesoup_to_unsign, &stonesoup_to_unsign, "CROSSOVER-STATE");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    stonesoup_file = fopen("/opt/stonesoup/workspace/testData/myfile.txt","r");
    if (stonesoup_file != 0) {
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
        while (((unsigned int )stonesoup_counter) < stonesoup_to_unsign) {
            /* STONESOUP: TRIGGER-POINT (Unexpected Sign Extension) */
            stonesoup_bytes_read = fread(&stonesoup_buff[stonesoup_counter],
                sizeof(char), 1000, stonesoup_file);
            if (stonesoup_bytes_read == 0) {
                break;
            }
            stonesoup_counter += stonesoup_bytes_read;
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
        fclose(stonesoup_file);
        stonesoup_buff[stonesoup_to_unsign] = '\0';
        stonesoup_printf("buff is %d long, and has contents: %s \n",strlen(stonesoup_buff), stonesoup_buff);
    } else {
        stonesoup_printf("Cannot open file %s\n", "/opt/stonesoup/workspace/testData/myfile.txt");
    }
    if (stonesoup_buff != 0) {
        free(stonesoup_buff);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((union hypoxemic_sasses )grayfishes_barbellulae) . binodous_guinean != 0) 
    free(((char *)((union hypoxemic_sasses )grayfishes_barbellulae) . binodous_guinean));
stonesoup_close_printf_context();
}

void blandishes_profitless(int manus_cembali,union hypoxemic_sasses verdelho_kratogen)
{
  ++stonesoup_global_variable;
  centetes_variegate(manus_cembali,verdelho_kratogen);
}
