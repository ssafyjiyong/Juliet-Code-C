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
int misresemblance_donought = 0;
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
void acroarthritis_coliidae(void ***********brahminist_jara);
void developmentist_slacks(void ***********aluconidae_belsire);
void evesham_tautens(void ***********mizoram_introd);
void suicidally_middle(void ***********outridden_finky);
void carinas_afterlifetime(void ***********pyrrhuloxia_resistive);
void swathed_gigging(void ***********butteris_polysorbate);
void yaff_colorationally(void ***********clinicist_shrimper);
void frolick_dididae(void ***********hungriest_hypothalamic);
void pallion_mccabe(void ***********madeiras_hoplocephalus);
void coddle_etalons(void ***********operatrix_tomial);
int stonesoup_returnChunkSize(void *dest,void *src)
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpYOrWOF_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_returnChunkSize");
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
  void ***********closure_zolotnik = 0;
  void **********nitrogenization_tiring = 0;
  void *********unmortalize_exogastric = 0;
  void ********nam_sloked = 0;
  void *******joneses_rehemming = 0;
  void ******navete_chattingly = 0;
  void *****upsloping_silencing = 0;
  void ****baptanodon_securigerous = 0;
  void ***unmelodiousness_amygdalic = 0;
  void **freeboard_gitonin = 0;
  void *pilger_autodrome = 0;
  void *obtusifid_wuhan = 0;
  char *ramiparous_stav;;
  if (__sync_bool_compare_and_swap(&misresemblance_donought,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpYOrWOF_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&ramiparous_stav,"DISSONANCE_SIMIANS");
      if (ramiparous_stav != 0) {;
        obtusifid_wuhan = ((void *)ramiparous_stav);
        freeboard_gitonin = &obtusifid_wuhan;
        unmelodiousness_amygdalic = &freeboard_gitonin;
        baptanodon_securigerous = &unmelodiousness_amygdalic;
        upsloping_silencing = &baptanodon_securigerous;
        navete_chattingly = &upsloping_silencing;
        joneses_rehemming = &navete_chattingly;
        nam_sloked = &joneses_rehemming;
        unmortalize_exogastric = &nam_sloked;
        nitrogenization_tiring = &unmortalize_exogastric;
        closure_zolotnik = &nitrogenization_tiring;
        acroarthritis_coliidae(closure_zolotnik);
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

void acroarthritis_coliidae(void ***********brahminist_jara)
{
  ++stonesoup_global_variable;;
  developmentist_slacks(brahminist_jara);
}

void developmentist_slacks(void ***********aluconidae_belsire)
{
  ++stonesoup_global_variable;;
  evesham_tautens(aluconidae_belsire);
}

void evesham_tautens(void ***********mizoram_introd)
{
  ++stonesoup_global_variable;;
  suicidally_middle(mizoram_introd);
}

void suicidally_middle(void ***********outridden_finky)
{
  ++stonesoup_global_variable;;
  carinas_afterlifetime(outridden_finky);
}

void carinas_afterlifetime(void ***********pyrrhuloxia_resistive)
{
  ++stonesoup_global_variable;;
  swathed_gigging(pyrrhuloxia_resistive);
}

void swathed_gigging(void ***********butteris_polysorbate)
{
  ++stonesoup_global_variable;;
  yaff_colorationally(butteris_polysorbate);
}

void yaff_colorationally(void ***********clinicist_shrimper)
{
  ++stonesoup_global_variable;;
  frolick_dididae(clinicist_shrimper);
}

void frolick_dididae(void ***********hungriest_hypothalamic)
{
  ++stonesoup_global_variable;;
  pallion_mccabe(hungriest_hypothalamic);
}

void pallion_mccabe(void ***********madeiras_hoplocephalus)
{
  ++stonesoup_global_variable;;
  coddle_etalons(madeiras_hoplocephalus);
}

void coddle_etalons(void ***********operatrix_tomial)
{
    const int stonesoup_MAXLEN = 16;
    char stonesoup_dest[stonesoup_MAXLEN];
    size_t stonesoup_size_var = 0;
  char *milliamperes_woa = 0;
  ++stonesoup_global_variable;;
  milliamperes_woa = ((char *)((char *)( *( *( *( *( *( *( *( *( *( *operatrix_tomial))))))))))));
    tracepoint(stonesoup_trace, weakness_start, "CWE195", "A", "Signed to Unsigned Conversion Error");
    memset(stonesoup_dest,'x',stonesoup_MAXLEN);
    stonesoup_dest[stonesoup_MAXLEN - 1] = '\0';
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_size_var = stonesoup_returnChunkSize(stonesoup_dest, milliamperes_woa);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_size_var", stonesoup_size_var, &stonesoup_size_var, "TRIGGER-STATE");
/* STONESOUP: TRIGGER-POINT (Signed To Unsigned Conversion Error) */
    if (stonesoup_size_var > 0)
        memcpy(stonesoup_dest, milliamperes_woa, stonesoup_size_var);
    stonesoup_printf("%s\n",stonesoup_dest);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (((char *)( *( *( *( *( *( *( *( *( *( *operatrix_tomial))))))))))) != 0) 
    free(((char *)((char *)( *( *( *( *( *( *( *( *( *( *operatrix_tomial)))))))))))));
stonesoup_close_printf_context();
}
