/*
 * svn_types.c :  Implementation for Subversion's data types.
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
#include <apr_pools.h>
#include <apr_uuid.h>
#include "svn_hash.h"
#include "svn_types.h"
#include "svn_error.h"
#include "svn_string.h"
#include "svn_props.h"
#include "svn_private_config.h"
#include <sys/stat.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
int delectation_dodonean = 0;
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
void tregerg_quadriannulate(char ***tettigoniidae_flashiest);
void sublumbar_preconclusion(char ***oversecurity_theaceae);
void swooningly_illuminations(char ***enterotoxemia_adaptors);
void viqueen_revelly(char ***culttelli_blackguard);
void expectorants_annates(char ***peroxisome_freyalite);
void marquisotte_skinflint(char ***chirrup_daffiest);
void smorzando_stories(char ***sclat_gasser);
void ushering_pikeville(char ***neurohumor_armorer);
void dalecarlian_mariologist(char ***armgaunt_cremations);
void familial_heptachronous(char ***pharo_bergomask);
void centriscoid_aragonian(char ***nounal_pyolymph);
void sukkoth_saddlebacked(char ***subtrigonal_hipped);
void pistonhead_shagreened(char ***polygony_pabulums);
void kanyaw_glirine(char ***hansard_enantiomorphic);
void marrowbones_misteacher(char ***succeeding_fantom);
void equestrianship_unsizeableness(char ***titheright_chirpiness);
void oversetting_panne(char ***pembine_mafias);
void philoradical_gobbin(char ***bilsted_shrinkable);
void vulgate_intransigency(char ***eranthemum_unhostile);
void gitalin_dibasic(char ***reactor_parentele);
void lochgelly_thecal(char ***ailurophilia_blennophlogisma);
void dreadly_mistassini(char ***pectinal_pongo);
void sapir_schistocephalus(char ***bequests_erotics);
void assigning_acetonate(char ***fourhanded_koreshanity);
void lamin_hemiscotosis(char ***mameliere_unsweetness);
void soleus_corvus(char ***excising_vertrees);
void memorialization_alniresinol(char ***epidia_waggled);
void fondant_dystectic(char ***stomachable_mancipant);
void lithophyllous_redux(char ***karole_personality);
void unconcluded_guy(char ***abirritate_misobservance);
void saggard_forecomingness(char ***adumbrated_garous);
void vibes_bowsman(char ***unintermittedly_productions);
void aurified_achango(char ***devanagari_unsagacious);
void inscious_menus(char ***beebee_decachord);
void simpled_thighs(char ***diaphototropic_acicularity);
void glick_marbrinus(char ***avocet_pandering);
void neutrodyne_simurgh(char ***pitchers_decoagulate);
void combretaceae_wincing(char ***overnurse_fulham);
void ilongot_realizability(char ***coseiest_federalizes);
void supersulphate_jewless(char ***causa_undrivableness);
void reusableness_readopt(char ***mincingly_rosamund);
void patrilinear_extol(char ***polyaemic_scouting);
void idealize_dentality(char ***complot_purveyed);
void clotho_hawkings(char ***evolutions_uniramose);
void npv_glenlyn(char ***idest_sculptography);
void vmm_brisance(char ***chocolates_cyathium);
void fortisan_counterword(char ***feckless_ayudhya);
void leakier_progenerative(char ***bulletlike_haleweed);
void anticlogging_southwest(char ***cleve_bilby);
void extrameridian_burdash(char ***hatcheler_bursitises);
struct stonesoup_data {
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
pthread_mutex_t stonesoup_mutex_0, stonesoup_mutex_1;
pthread_t stonesoup_t0, stonesoup_t1;
int stonesoup_comp (const void * a, const void * b)
{
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
int stonesoup_pmoc (const void * a, const void * b)
{
    return -1 * stonesoup_comp(a, b);
}
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpISlu79_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *stonesoup_replace (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int *qsort_arr;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpISlu79_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_replace");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    stonesoup_printf("replace: entering function\n");
    /* slow things down to make correct thing happen in good cases */
    qsort_arr = malloc(sizeof(int)*stonesoupData->qsize);
    if (qsort_arr != NULL) {
        for (i = 0; i < stonesoupData->qsize; i++) {
            qsort_arr[i] = stonesoupData->qsize - i;
        }
        qsort(qsort_arr, stonesoupData->qsize, sizeof(int), &stonesoup_comp);
        free (qsort_arr);
        qsort_arr = NULL;
    }
    stonesoup_readFile(stonesoupData->file1);
    stonesoup_printf("replace: Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0);
    stonesoup_printf("replace: Grabbed lock 0\n");
    stonesoup_printf("replace: Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1); /* DEADLOCK */
    stonesoup_printf("replace: Grabbed lock 1\n");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] == '_') {
            stonesoupData->data[i] = '-';
        }
        i++;
    }
    stonesoup_printf("replace: Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    stonesoup_printf("replace: Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    return NULL;
}
void *stonesoup_toCap (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*)data;
    int i = 0;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpISlu79_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_toCap");
    stonesoup_printf("toCap:   Entering function\n");
    stonesoup_printf("toCap:   Attempting to grab lock 1\n");
    pthread_mutex_lock(&stonesoup_mutex_1);
    stonesoup_printf("toCap:   Grabbed lock 1\n");
    stonesoup_readFile(stonesoupData->file2);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (deadlock) */
    stonesoup_printf("toCap:   Attempting to grab lock 0\n");
    pthread_mutex_lock(&stonesoup_mutex_0); /* DEADLOCK */
    stonesoup_printf("toCap:   Grabbed lock 0\n");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    i = 0;
    while(stonesoupData->data[i] != '\0') {
        if (stonesoupData->data[i] > 'a' && stonesoupData->data[i] < 'z') {
            stonesoupData->data[i] -= 'a' - 'A';
        }
        i++;
    }
    stonesoup_printf("toCap:   Releasing lock 0\n");
    pthread_mutex_unlock(&stonesoup_mutex_0);
    stonesoup_printf("toCap:   Releasing lock 1\n");
    pthread_mutex_unlock(&stonesoup_mutex_1);
    return NULL;
}

svn_error_t *svn_revnum_parse(svn_revnum_t *rev,const char *str,const char **endptr)
{
  char *end;
  svn_revnum_t result = strtol(str,&end,10);
  if (endptr) {
     *endptr = end;
  }
  if (str == end) {
    return svn_error_createf(SVN_ERR_REVNUM_PARSE_FAILURE,((void *)0),(dgettext("subversion","Invalid revision number found parsing '%s'")),str);
  }
  if (result < 0) {
/* The end pointer from strtol() is valid, but a negative revision
         number is invalid, so move the end pointer back to the
         beginning of the string. */
    if (endptr) {
       *endptr = str;
    }
    return svn_error_createf(SVN_ERR_REVNUM_PARSE_FAILURE,((void *)0),(dgettext("subversion","Negative revision number found parsing '%s'")),str);
  }
   *rev = result;
  return 0;
}

const char *svn_uuid_generate(apr_pool_t *pool)
{
  apr_uuid_t uuid;
  char *uuid_str = (memset(apr_palloc(pool,(36 + 1)),0,(36 + 1)));
  apr_uuid_get(&uuid);
  apr_uuid_format(uuid_str,(&uuid));
  return uuid_str;
}

const char *svn_depth_to_word(svn_depth_t depth)
{
  switch(depth){
    case svn_depth_exclude:
    return "exclude";
    case svn_depth_unknown:
    return "unknown";
    case svn_depth_empty:
    return "empty";
    case svn_depth_files:
    return "files";
    case svn_depth_immediates:
    return "immediates";
    case svn_depth_infinity:
    return "infinity";
    default:
    return "INVALID-DEPTH";
  }
}

svn_depth_t svn_depth_from_word(const char *word)
{
  if (strcmp(word,"exclude") == 0) {
    return svn_depth_exclude;
  }
  if (strcmp(word,"unknown") == 0) {
    return svn_depth_unknown;
  }
  if (strcmp(word,"empty") == 0) {
    return svn_depth_empty;
  }
  if (strcmp(word,"files") == 0) {
    return svn_depth_files;
  }
  if (strcmp(word,"immediates") == 0) {
    return svn_depth_immediates;
  }
  if (strcmp(word,"infinity") == 0) {
    return svn_depth_infinity;
  }
/* There's no special value for invalid depth, and no convincing
     reason to make one yet, so just fall back to unknown depth.
     If you ever change that convention, check callers to make sure
     they're not depending on it (e.g., option parsing in main() ).
  */
  return svn_depth_unknown;
}

const char *svn_node_kind_to_word(svn_node_kind_t kind)
{
  switch(kind){
    case svn_node_none:
    return "none";
    case svn_node_file:
    return "file";
    case svn_node_dir:
    return "dir";
    case svn_node_symlink:
    return "symlink";
    case svn_node_unknown:
{
    }
    default:
    return "unknown";
  }
}

svn_node_kind_t svn_node_kind_from_word(const char *word)
{
  if (word == ((void *)0)) {
    return svn_node_unknown;
  }
  if (strcmp(word,"none") == 0) {
    return svn_node_none;
  }
  else {
    if (strcmp(word,"file") == 0) {
      return svn_node_file;
    }
    else {
      if (strcmp(word,"dir") == 0) {
        return svn_node_dir;
      }
      else {
        if (strcmp(word,"symlink") == 0) {
          return svn_node_symlink;
        }
        else {
/* This also handles word == "unknown" */
          return svn_node_unknown;
        }
      }
    }
  }
}

const char *svn_tristate__to_word(svn_tristate_t tristate)
{
  switch(tristate){
    case svn_tristate_false:
    return "false";
    case svn_tristate_true:
    return "true";
    case svn_tristate_unknown:
{
    }
    default:
    return ((void *)0);
  }
}

svn_tristate_t svn_tristate__from_word(const char *word)
{
  char ***concertment_downey = 0;
  char **cajoler_unregular = 0;
  char *uptight_minning = 0;
  char *precomposition_chilotomy;;
  if (__sync_bool_compare_and_swap(&delectation_dodonean,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpISlu79_ss_testcase/src-rose/subversion/libsvn_subr/types.c","svn_tristate__from_word");
      stonesoup_setup_printf_context();
      precomposition_chilotomy = getenv("PUTSCH_SHALLOTTE");
      if (precomposition_chilotomy != 0) {;
        cajoler_unregular = &precomposition_chilotomy;
        concertment_downey = &cajoler_unregular;
        tregerg_quadriannulate(concertment_downey);
      }
    }
  }
  ;
  if (word == ((void *)0)) {
    return svn_tristate_unknown;
  }
  else {
    if (0 == svn_cstring_casecmp(word,"true") || 0 == svn_cstring_casecmp(word,"yes") || 0 == svn_cstring_casecmp(word,"on") || 0 == strcmp(word,"1")) {
      return svn_tristate_true;
    }
    else {
      if (0 == svn_cstring_casecmp(word,"false") || 0 == svn_cstring_casecmp(word,"no") || 0 == svn_cstring_casecmp(word,"off") || 0 == strcmp(word,"0")) {
        return svn_tristate_false;
      }
    }
  }
  return svn_tristate_unknown;
}

svn_commit_info_t *svn_create_commit_info(apr_pool_t *pool)
{
  svn_commit_info_t *commit_info = (memset(apr_palloc(pool,sizeof(( *commit_info))),0,sizeof(( *commit_info))));
  commit_info -> revision = ((svn_revnum_t )(- 1));
/* All other fields were initialized to NULL above. */
  return commit_info;
}

svn_commit_info_t *svn_commit_info_dup(const svn_commit_info_t *src_commit_info,apr_pool_t *pool)
{
  svn_commit_info_t *dst_commit_info = (apr_palloc(pool,sizeof(( *dst_commit_info))));
  dst_commit_info -> date = ((src_commit_info -> date?apr_pstrdup(pool,src_commit_info -> date) : ((void *)0)));
  dst_commit_info -> author = ((src_commit_info -> author?apr_pstrdup(pool,src_commit_info -> author) : ((void *)0)));
  dst_commit_info -> revision = src_commit_info -> revision;
  dst_commit_info -> post_commit_err = ((src_commit_info -> post_commit_err?apr_pstrdup(pool,src_commit_info -> post_commit_err) : ((void *)0)));
  dst_commit_info -> repos_root = ((src_commit_info -> repos_root?apr_pstrdup(pool,src_commit_info -> repos_root) : ((void *)0)));
  return dst_commit_info;
}

svn_log_changed_path2_t *svn_log_changed_path2_create(apr_pool_t *pool)
{
  svn_log_changed_path2_t *new_changed_path = (memset(apr_palloc(pool,sizeof(( *new_changed_path))),0,sizeof(( *new_changed_path))));
  new_changed_path -> text_modified = svn_tristate_unknown;
  new_changed_path -> props_modified = svn_tristate_unknown;
  return new_changed_path;
}

svn_log_changed_path2_t *svn_log_changed_path2_dup(const svn_log_changed_path2_t *changed_path,apr_pool_t *pool)
{
  svn_log_changed_path2_t *new_changed_path = (apr_palloc(pool,sizeof(( *new_changed_path))));
   *new_changed_path =  *changed_path;
  if (new_changed_path -> copyfrom_path) {
    new_changed_path -> copyfrom_path = (apr_pstrdup(pool,new_changed_path -> copyfrom_path));
  }
  return new_changed_path;
}

svn_dirent_t *svn_dirent_create(apr_pool_t *result_pool)
{
  svn_dirent_t *new_dirent = (memset(apr_palloc(result_pool,sizeof(( *new_dirent))),0,sizeof(( *new_dirent))));
  new_dirent -> kind = svn_node_unknown;
  new_dirent -> size = ((svn_filesize_t )(- 1));
  new_dirent -> created_rev = ((svn_revnum_t )(- 1));
  new_dirent -> time = 0;
  new_dirent -> last_author = ((void *)0);
  return new_dirent;
}

svn_dirent_t *svn_dirent_dup(const svn_dirent_t *dirent,apr_pool_t *pool)
{
  svn_dirent_t *new_dirent = (apr_palloc(pool,sizeof(( *new_dirent))));
   *new_dirent =  *dirent;
  new_dirent -> last_author = (apr_pstrdup(pool,dirent -> last_author));
  return new_dirent;
}

svn_log_entry_t *svn_log_entry_create(apr_pool_t *pool)
{
  svn_log_entry_t *log_entry = (memset(apr_palloc(pool,sizeof(( *log_entry))),0,sizeof(( *log_entry))));
  return log_entry;
}

svn_log_entry_t *svn_log_entry_dup(const svn_log_entry_t *log_entry,apr_pool_t *pool)
{
  apr_hash_index_t *hi;
  svn_log_entry_t *new_entry = (apr_palloc(pool,sizeof(( *new_entry))));
   *new_entry =  *log_entry;
  if (log_entry -> revprops) {
    new_entry -> revprops = svn_prop_hash_dup((log_entry -> revprops),pool);
  }
  if (log_entry -> changed_paths2) {
    new_entry -> changed_paths2 = apr_hash_make(pool);
    for (hi = apr_hash_first(pool,log_entry -> changed_paths2); hi; hi = apr_hash_next(hi)) {
      const void *key;
      void *change;
      apr_hash_this(hi,&key,((void *)0),&change);
      apr_hash_set(new_entry -> changed_paths2,(apr_pstrdup(pool,key)),(- 1),(svn_log_changed_path2_dup(change,pool)));
    }
  }
/* We can't copy changed_paths by itself without using deprecated code,
     but we don't have to, as this function was new after the introduction
     of the changed_paths2 field. */
  new_entry -> changed_paths = new_entry -> changed_paths2;
  return new_entry;
}

svn_location_segment_t *svn_location_segment_dup(const svn_location_segment_t *segment,apr_pool_t *pool)
{
  svn_location_segment_t *new_segment = (apr_palloc(pool,sizeof(( *new_segment))));
   *new_segment =  *segment;
  if (segment -> path) {
    new_segment -> path = (apr_pstrdup(pool,segment -> path));
  }
  return new_segment;
}

void tregerg_quadriannulate(char ***tettigoniidae_flashiest)
{
  ++stonesoup_global_variable;;
  sublumbar_preconclusion(tettigoniidae_flashiest);
}

void sublumbar_preconclusion(char ***oversecurity_theaceae)
{
  ++stonesoup_global_variable;;
  swooningly_illuminations(oversecurity_theaceae);
}

void swooningly_illuminations(char ***enterotoxemia_adaptors)
{
  ++stonesoup_global_variable;;
  viqueen_revelly(enterotoxemia_adaptors);
}

void viqueen_revelly(char ***culttelli_blackguard)
{
  ++stonesoup_global_variable;;
  expectorants_annates(culttelli_blackguard);
}

void expectorants_annates(char ***peroxisome_freyalite)
{
  ++stonesoup_global_variable;;
  marquisotte_skinflint(peroxisome_freyalite);
}

void marquisotte_skinflint(char ***chirrup_daffiest)
{
  ++stonesoup_global_variable;;
  smorzando_stories(chirrup_daffiest);
}

void smorzando_stories(char ***sclat_gasser)
{
  ++stonesoup_global_variable;;
  ushering_pikeville(sclat_gasser);
}

void ushering_pikeville(char ***neurohumor_armorer)
{
  ++stonesoup_global_variable;;
  dalecarlian_mariologist(neurohumor_armorer);
}

void dalecarlian_mariologist(char ***armgaunt_cremations)
{
  ++stonesoup_global_variable;;
  familial_heptachronous(armgaunt_cremations);
}

void familial_heptachronous(char ***pharo_bergomask)
{
  ++stonesoup_global_variable;;
  centriscoid_aragonian(pharo_bergomask);
}

void centriscoid_aragonian(char ***nounal_pyolymph)
{
  ++stonesoup_global_variable;;
  sukkoth_saddlebacked(nounal_pyolymph);
}

void sukkoth_saddlebacked(char ***subtrigonal_hipped)
{
  ++stonesoup_global_variable;;
  pistonhead_shagreened(subtrigonal_hipped);
}

void pistonhead_shagreened(char ***polygony_pabulums)
{
  ++stonesoup_global_variable;;
  kanyaw_glirine(polygony_pabulums);
}

void kanyaw_glirine(char ***hansard_enantiomorphic)
{
  ++stonesoup_global_variable;;
  marrowbones_misteacher(hansard_enantiomorphic);
}

void marrowbones_misteacher(char ***succeeding_fantom)
{
  ++stonesoup_global_variable;;
  equestrianship_unsizeableness(succeeding_fantom);
}

void equestrianship_unsizeableness(char ***titheright_chirpiness)
{
  ++stonesoup_global_variable;;
  oversetting_panne(titheright_chirpiness);
}

void oversetting_panne(char ***pembine_mafias)
{
  ++stonesoup_global_variable;;
  philoradical_gobbin(pembine_mafias);
}

void philoradical_gobbin(char ***bilsted_shrinkable)
{
  ++stonesoup_global_variable;;
  vulgate_intransigency(bilsted_shrinkable);
}

void vulgate_intransigency(char ***eranthemum_unhostile)
{
  ++stonesoup_global_variable;;
  gitalin_dibasic(eranthemum_unhostile);
}

void gitalin_dibasic(char ***reactor_parentele)
{
  ++stonesoup_global_variable;;
  lochgelly_thecal(reactor_parentele);
}

void lochgelly_thecal(char ***ailurophilia_blennophlogisma)
{
  ++stonesoup_global_variable;;
  dreadly_mistassini(ailurophilia_blennophlogisma);
}

void dreadly_mistassini(char ***pectinal_pongo)
{
  ++stonesoup_global_variable;;
  sapir_schistocephalus(pectinal_pongo);
}

void sapir_schistocephalus(char ***bequests_erotics)
{
  ++stonesoup_global_variable;;
  assigning_acetonate(bequests_erotics);
}

void assigning_acetonate(char ***fourhanded_koreshanity)
{
  ++stonesoup_global_variable;;
  lamin_hemiscotosis(fourhanded_koreshanity);
}

void lamin_hemiscotosis(char ***mameliere_unsweetness)
{
  ++stonesoup_global_variable;;
  soleus_corvus(mameliere_unsweetness);
}

void soleus_corvus(char ***excising_vertrees)
{
  ++stonesoup_global_variable;;
  memorialization_alniresinol(excising_vertrees);
}

void memorialization_alniresinol(char ***epidia_waggled)
{
  ++stonesoup_global_variable;;
  fondant_dystectic(epidia_waggled);
}

void fondant_dystectic(char ***stomachable_mancipant)
{
  ++stonesoup_global_variable;;
  lithophyllous_redux(stomachable_mancipant);
}

void lithophyllous_redux(char ***karole_personality)
{
  ++stonesoup_global_variable;;
  unconcluded_guy(karole_personality);
}

void unconcluded_guy(char ***abirritate_misobservance)
{
  ++stonesoup_global_variable;;
  saggard_forecomingness(abirritate_misobservance);
}

void saggard_forecomingness(char ***adumbrated_garous)
{
  ++stonesoup_global_variable;;
  vibes_bowsman(adumbrated_garous);
}

void vibes_bowsman(char ***unintermittedly_productions)
{
  ++stonesoup_global_variable;;
  aurified_achango(unintermittedly_productions);
}

void aurified_achango(char ***devanagari_unsagacious)
{
  ++stonesoup_global_variable;;
  inscious_menus(devanagari_unsagacious);
}

void inscious_menus(char ***beebee_decachord)
{
  ++stonesoup_global_variable;;
  simpled_thighs(beebee_decachord);
}

void simpled_thighs(char ***diaphototropic_acicularity)
{
  ++stonesoup_global_variable;;
  glick_marbrinus(diaphototropic_acicularity);
}

void glick_marbrinus(char ***avocet_pandering)
{
  ++stonesoup_global_variable;;
  neutrodyne_simurgh(avocet_pandering);
}

void neutrodyne_simurgh(char ***pitchers_decoagulate)
{
  ++stonesoup_global_variable;;
  combretaceae_wincing(pitchers_decoagulate);
}

void combretaceae_wincing(char ***overnurse_fulham)
{
  ++stonesoup_global_variable;;
  ilongot_realizability(overnurse_fulham);
}

void ilongot_realizability(char ***coseiest_federalizes)
{
  ++stonesoup_global_variable;;
  supersulphate_jewless(coseiest_federalizes);
}

void supersulphate_jewless(char ***causa_undrivableness)
{
  ++stonesoup_global_variable;;
  reusableness_readopt(causa_undrivableness);
}

void reusableness_readopt(char ***mincingly_rosamund)
{
  ++stonesoup_global_variable;;
  patrilinear_extol(mincingly_rosamund);
}

void patrilinear_extol(char ***polyaemic_scouting)
{
  ++stonesoup_global_variable;;
  idealize_dentality(polyaemic_scouting);
}

void idealize_dentality(char ***complot_purveyed)
{
  ++stonesoup_global_variable;;
  clotho_hawkings(complot_purveyed);
}

void clotho_hawkings(char ***evolutions_uniramose)
{
  ++stonesoup_global_variable;;
  npv_glenlyn(evolutions_uniramose);
}

void npv_glenlyn(char ***idest_sculptography)
{
  ++stonesoup_global_variable;;
  vmm_brisance(idest_sculptography);
}

void vmm_brisance(char ***chocolates_cyathium)
{
  ++stonesoup_global_variable;;
  fortisan_counterword(chocolates_cyathium);
}

void fortisan_counterword(char ***feckless_ayudhya)
{
  ++stonesoup_global_variable;;
  leakier_progenerative(feckless_ayudhya);
}

void leakier_progenerative(char ***bulletlike_haleweed)
{
  ++stonesoup_global_variable;;
  anticlogging_southwest(bulletlike_haleweed);
}

void anticlogging_southwest(char ***cleve_bilby)
{
  ++stonesoup_global_variable;;
  extrameridian_burdash(cleve_bilby);
}

void extrameridian_burdash(char ***hatcheler_bursitises)
{
    int stonesoup_hasUnderscores = 0;
    int stonesoup_i = 0;
    struct stonesoup_data* stonesoupData;
  char *homer_carvestrene = 0;
  ++stonesoup_global_variable;;
  homer_carvestrene = ((char *)( *( *hatcheler_bursitises)));
    tracepoint(stonesoup_trace, weakness_start, "CWE833", "A", "Deadlock");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(homer_carvestrene) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(homer_carvestrene) + 1));
        stonesoupData->file2 = malloc(sizeof(char) * (strlen(homer_carvestrene) + 1));
        if (stonesoupData->data) {
            if ((sscanf(homer_carvestrene, "%d %s %s %s",
                      &(stonesoupData->qsize),
                        stonesoupData->file1,
                        stonesoupData->file2,
                        stonesoupData->data) == 4) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0) &&
                (strlen(stonesoupData->file2) != 0))
            {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", stonesoupData->qsize, &(stonesoupData->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", stonesoupData->file2, "INITIAL-STATE");
                pthread_mutex_init(&stonesoup_mutex_0, NULL);
                pthread_mutex_init(&stonesoup_mutex_1, NULL);
                while(stonesoupData->data[stonesoup_i] != '\0') { /* if the input contains underscores */
                    if (stonesoupData->data[stonesoup_i++] == '_') { /*   we call the deadlocking function */
                        stonesoup_hasUnderscores = 1;
                    }
                }
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, stonesoup_toCap, stonesoupData) != 0) {
                    stonesoup_printf("Thread 0 failed to spawn.");
                }
                if (stonesoup_hasUnderscores == 1) {
                    /* STONESOUP: CROSSOVER-POINT (deadlock) */
                    if (pthread_create(&stonesoup_t1, NULL, stonesoup_replace, stonesoupData) != 0) {
                        stonesoup_printf("Thread 1 failed to spawn.");
                    }
                }
                pthread_join(stonesoup_t0, NULL);
                if (stonesoup_hasUnderscores == 1) {
                    pthread_join(stonesoup_t1, NULL);
                }
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
                pthread_mutex_destroy(&stonesoup_mutex_0);
                pthread_mutex_destroy(&stonesoup_mutex_1);
            } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data");
                stonesoup_printf("Error parsing data\n");
            }
            free(stonesoupData->data);
        }
        free(stonesoupData);
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}
