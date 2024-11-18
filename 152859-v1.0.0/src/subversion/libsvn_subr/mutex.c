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
#include <ctype.h> 
int linz_defenselessness = 0;
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
void patmo_marsala(char **nostoc_abbreviatable);
void wiste_quadridigitate(char **sippers_sicambrian);
void urlDecode(char *src, char *dst) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
                ((a = src[1]) && (b = src[2])) &&
                (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a'-'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a'-'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}
int isValid(char *src) {
    int i = 0;
    while (src[i] != '\0') {
        if(src[i] == ';') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        else if(src[i] == '|') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        else if(src[i] == '&') {
            if (i == 0 || src[i-1] != '\\') {
                return 0;
            }
        }
        i++;
    }
    return 1;
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
  char **erythrophage_apodictically = 0;
  int **************************************************machairodus_idolatrized = 0;
  int *************************************************callout_missis = 0;
  int ************************************************androdynamous_caratch = 0;
  int ***********************************************heterodera_costing = 0;
  int **********************************************pseudomonades_biporous = 0;
  int *********************************************fulk_dst = 0;
  int ********************************************narica_usecc = 0;
  int *******************************************spiritleaf_magnesia = 0;
  int ******************************************oscilloscopes_rajahs = 0;
  int *****************************************disavowed_wigner = 0;
  int ****************************************snootiness_phthalanilic = 0;
  int ***************************************magh_explorativeness = 0;
  int **************************************waiting_habenar = 0;
  int *************************************alcahest_beclowned = 0;
  int ************************************callously_voyager = 0;
  int ***********************************dichopodial_ecstatic = 0;
  int **********************************dimpling_supermolecule = 0;
  int *********************************rhamnus_reptilism = 0;
  int ********************************adducted_sheakleyville = 0;
  int *******************************becheck_sevenscore = 0;
  int ******************************reemphasis_teutophil = 0;
  int *****************************massebah_intrenching = 0;
  int ****************************relaxable_uninhumed = 0;
  int ***************************hightails_basilisks = 0;
  int **************************reflexional_lakie = 0;
  int *************************hut_ohone = 0;
  int ************************sweetbriar_acridophagus = 0;
  int ***********************synoicousness_shivered = 0;
  int **********************linteling_underworlds = 0;
  int *********************hitchproof_coziness = 0;
  int ********************rodenhouse_waicuri = 0;
  int *******************unrenounceable_fingerprinted = 0;
  int ******************tzaritza_fiorite = 0;
  int *****************stomachers_uncollectibly = 0;
  int ****************mbps_pelodytidae = 0;
  int ***************reimbursement_debugged = 0;
  int **************commelinaceae_zabra = 0;
  int *************brauhauser_wiota = 0;
  int ************soyas_ramean = 0;
  int ***********boh_huxleyan = 0;
  int **********peroneotarsal_erogenesis = 0;
  int *********foreseeing_bivalency = 0;
  int ********strelitz_pratdesaba = 0;
  int *******hypotyposis_molybdocolic = 0;
  int ******unstatically_hoplonemertine = 0;
  int *****pleomorphism_uri = 0;
  int ****delma_preutilize = 0;
  int ***geothlypis_rocky = 0;
  int **assahy_uneasily = 0;
  int *limnery_sundance = 0;
  int nonpresidential_kingbolt;
  char **unchanged_superenrollment[10] = {0};
  char *becombed_thousandweight[77] = {0};
  char *unowing_uncavilling;;
  if (__sync_bool_compare_and_swap(&linz_defenselessness,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpca6LkP_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&unowing_uncavilling,"PYROLYTIC_DNIREN");
      if (unowing_uncavilling != 0) {;
        becombed_thousandweight[9] = unowing_uncavilling;
        nonpresidential_kingbolt = 5;
        limnery_sundance = &nonpresidential_kingbolt;
        assahy_uneasily = &limnery_sundance;
        geothlypis_rocky = &assahy_uneasily;
        delma_preutilize = &geothlypis_rocky;
        pleomorphism_uri = &delma_preutilize;
        unstatically_hoplonemertine = &pleomorphism_uri;
        hypotyposis_molybdocolic = &unstatically_hoplonemertine;
        strelitz_pratdesaba = &hypotyposis_molybdocolic;
        foreseeing_bivalency = &strelitz_pratdesaba;
        peroneotarsal_erogenesis = &foreseeing_bivalency;
        boh_huxleyan = &peroneotarsal_erogenesis;
        soyas_ramean = &boh_huxleyan;
        brauhauser_wiota = &soyas_ramean;
        commelinaceae_zabra = &brauhauser_wiota;
        reimbursement_debugged = &commelinaceae_zabra;
        mbps_pelodytidae = &reimbursement_debugged;
        stomachers_uncollectibly = &mbps_pelodytidae;
        tzaritza_fiorite = &stomachers_uncollectibly;
        unrenounceable_fingerprinted = &tzaritza_fiorite;
        rodenhouse_waicuri = &unrenounceable_fingerprinted;
        hitchproof_coziness = &rodenhouse_waicuri;
        linteling_underworlds = &hitchproof_coziness;
        synoicousness_shivered = &linteling_underworlds;
        sweetbriar_acridophagus = &synoicousness_shivered;
        hut_ohone = &sweetbriar_acridophagus;
        reflexional_lakie = &hut_ohone;
        hightails_basilisks = &reflexional_lakie;
        relaxable_uninhumed = &hightails_basilisks;
        massebah_intrenching = &relaxable_uninhumed;
        reemphasis_teutophil = &massebah_intrenching;
        becheck_sevenscore = &reemphasis_teutophil;
        adducted_sheakleyville = &becheck_sevenscore;
        rhamnus_reptilism = &adducted_sheakleyville;
        dimpling_supermolecule = &rhamnus_reptilism;
        dichopodial_ecstatic = &dimpling_supermolecule;
        callously_voyager = &dichopodial_ecstatic;
        alcahest_beclowned = &callously_voyager;
        waiting_habenar = &alcahest_beclowned;
        magh_explorativeness = &waiting_habenar;
        snootiness_phthalanilic = &magh_explorativeness;
        disavowed_wigner = &snootiness_phthalanilic;
        oscilloscopes_rajahs = &disavowed_wigner;
        spiritleaf_magnesia = &oscilloscopes_rajahs;
        narica_usecc = &spiritleaf_magnesia;
        fulk_dst = &narica_usecc;
        pseudomonades_biporous = &fulk_dst;
        heterodera_costing = &pseudomonades_biporous;
        androdynamous_caratch = &heterodera_costing;
        callout_missis = &androdynamous_caratch;
        machairodus_idolatrized = &callout_missis;
        unchanged_superenrollment[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *machairodus_idolatrized)))))))))))))))))))))))))))))))))))))))))))))))))] = becombed_thousandweight;
        erythrophage_apodictically = unchanged_superenrollment[ *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *( *machairodus_idolatrized)))))))))))))))))))))))))))))))))))))))))))))))))];
        patmo_marsala(erythrophage_apodictically);
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

void patmo_marsala(char **nostoc_abbreviatable)
{
  ++stonesoup_global_variable;;
  wiste_quadridigitate(nostoc_abbreviatable);
}

void wiste_quadridigitate(char **sippers_sicambrian)
{
    FILE *stonesoup_fpipe;
    char stonesoup_buffer[100];
    char *stonesoup_parsed_input;
    char stonesoup_command_buffer[1000];
    char *stonesoup_command_str = "nslookup ";
  char *sulky_tompkinsville = 0;
  ++stonesoup_global_variable;;
  sulky_tompkinsville = ((char *)sippers_sicambrian[9]);
    tracepoint(stonesoup_trace, weakness_start, "CWE078", "A", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')");
    if (strlen(sulky_tompkinsville) < 1000 - strlen(stonesoup_command_str)) {
        tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", sulky_tompkinsville, "INITIAL-STATE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        /* STONESOUP: CROSSOVER-POINT (OS Command Injection) */
        if (isValid(sulky_tompkinsville) == 1) {
            stonesoup_parsed_input = malloc((strlen(sulky_tompkinsville)+1) * sizeof(char));
            urlDecode(sulky_tompkinsville, stonesoup_parsed_input);
            snprintf(stonesoup_command_buffer, 1000, "%s%s",stonesoup_command_str, stonesoup_parsed_input);
            tracepoint(stonesoup_trace, variable_buffer, "stonesoup_command_buffer", stonesoup_command_buffer, "CROSSOVER-STATE");
            tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
            tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
            /* STONESOUP: TRIGGER-POINT (OS Command Injection) */
            stonesoup_fpipe = popen(stonesoup_command_buffer,"r");
            if (stonesoup_fpipe != 0) {
                while(fgets(stonesoup_buffer,100,stonesoup_fpipe) != 0) {
                    stonesoup_printf(stonesoup_buffer);
                }
                pclose(stonesoup_fpipe);
            }
        }
        tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
  if (sippers_sicambrian[9] != 0) 
    free(((char *)sippers_sicambrian[9]));
stonesoup_close_printf_context();
}
