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
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <pthread.h> 
int regulatorship_ethanoyl = 0;

struct rationment_muscari 
{
  char *fullerton_uprootal;
  double blasphemes_overpepper;
  char *sirsalis_secureness;
  char nuzzerana_valerians;
  int syzygy_essonne;
}
;
int stonesoup_global_variable;
void reapproved_formicine(struct rationment_muscari *demonetisation_tendency);
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
void bridesman_resaying(void (*eurafrican_unstrictly)(struct rationment_muscari *));
void recalculated_overscrub(int demotist_scleritic,... );
struct stonesoup_data {
    int inc_amount;
    int qsize;
    char *data;
    char *file1;
    char *file2;
};
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
void stonesoup_readFile(char *filename) {
    FILE *fifo;
    char ch;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpsF5yQS_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file.");
}
void *calcIncamount(void *data) {
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    stonesoup_printf("In calcInamount\n");
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpsF5yQS_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "calcIncamount");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    /* STONESOUP: CROSSOVER-POINT (missing syncronization) */
    dataStruct->inc_amount = dataStruct->data[0] - 'A'; /* oops...um... */
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "CROSSOVER-STATE");
    stonesoup_readFile(dataStruct->file2);
    if (dataStruct->inc_amount < 0) { /* let's just clean up and */
        dataStruct->inc_amount *= -1; /*  pretend that never happened */
    }
    else if (dataStruct->inc_amount == 0) { /*  shhhh */
        dataStruct->inc_amount += 1;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "FINAL-STATE");
    return NULL;
}
void *toPound(void *data) {
    int stonesoup_i;
    struct stonesoup_data *dataStruct = (struct stonesoup_data*)data;
    int *stonesoup_arr = NULL;
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpsF5yQS_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "toPound");
    stonesoup_printf("In toPound\n");
    /* slow things down to make correct thing happen in good cases */
    stonesoup_arr = malloc(sizeof(int) * dataStruct->qsize);
    for (stonesoup_i = 0; stonesoup_i < dataStruct->qsize; stonesoup_i++) {
        stonesoup_arr[stonesoup_i] = dataStruct->qsize - stonesoup_i;
    }
    qsort(stonesoup_arr, dataStruct->qsize, sizeof(int), &stonesoup_comp);
    free(stonesoup_arr);
    stonesoup_readFile(dataStruct->file1);
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_signed_integral, "dataStruct->inc_amount", dataStruct->inc_amount, &dataStruct->inc_amount, "TRIGGER-STATE");
    /* STONESOUP: TRIGGER-POINT (missing syncronization) */
    for (stonesoup_i = 0; stonesoup_i < (int)strlen(dataStruct->data) - 1;
         stonesoup_i += dataStruct->inc_amount) /* can cause underread/write if */
    {
        dataStruct->data[stonesoup_i] = '#'; /* stonesoup_increment_amount is neg */
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
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
{;
  if (__sync_bool_compare_and_swap(&regulatorship_ethanoyl,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpsF5yQS_ss_testcase/src-rose/subversion/libsvn_subr/types.c","svn_tristate__from_word");
      bridesman_resaying(reapproved_formicine);
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

void reapproved_formicine(struct rationment_muscari *demonetisation_tendency)
{
  struct rationment_muscari deflagrates_mocmain;
  char *vasileior_depositional;
  ++stonesoup_global_variable;;
  stonesoup_setup_printf_context();
  vasileior_depositional = getenv("TERRY_METAPOPHYSEAL");
  if (vasileior_depositional != 0) {;
    deflagrates_mocmain . fullerton_uprootal = ((char *)vasileior_depositional);
     *demonetisation_tendency = deflagrates_mocmain;
  }
}

void bridesman_resaying(void (*eurafrican_unstrictly)(struct rationment_muscari *))
{
  ++stonesoup_global_variable;
  struct rationment_muscari nonneutrality_disbranching = {0};
  eurafrican_unstrictly(&nonneutrality_disbranching);
  if (nonneutrality_disbranching . fullerton_uprootal != 0) {;
    recalculated_overscrub(1,nonneutrality_disbranching);
  }
}

void recalculated_overscrub(int demotist_scleritic,... )
{
    pthread_t stonesoup_t0, stonesoup_t1;
    struct stonesoup_data *dataStruct = malloc(sizeof(struct stonesoup_data));
  char *proangiospermic_strigillose = 0;
  struct rationment_muscari crampedness_extraviolet = {0};
  va_list spirochaetotic_switchboards;
  ++stonesoup_global_variable;;
  if (demotist_scleritic > 0) {
    __builtin_va_start(spirochaetotic_switchboards,demotist_scleritic);
    crampedness_extraviolet = (va_arg(spirochaetotic_switchboards,struct rationment_muscari ));
    __builtin_va_end(spirochaetotic_switchboards);
  }
  proangiospermic_strigillose = ((char *)crampedness_extraviolet . fullerton_uprootal);
    tracepoint(stonesoup_trace, weakness_start, "CWE820", "A", "Missing Synchronization");
    if (dataStruct) {
        dataStruct->inc_amount = 1;
        dataStruct->data = malloc(sizeof(char) * (strlen(proangiospermic_strigillose) + 1));
        dataStruct->file1 = malloc(sizeof(char) * (strlen(proangiospermic_strigillose) + 1));
        dataStruct->file2 = malloc(sizeof(char) * (strlen(proangiospermic_strigillose) + 1));
        if (dataStruct->data) {
            if ((sscanf(proangiospermic_strigillose, "%d %s %s %s",
                      &(dataStruct->qsize),
                        dataStruct->file1,
                        dataStruct->file2,
                        dataStruct->data) == 4) &&
                (strlen(dataStruct->data) != 0) &&
                (strlen(dataStruct->file1) != 0) &&
                (strlen(dataStruct->file2) != 0)) {
                tracepoint(stonesoup_trace, variable_signed_integral, "stonesoupData->qsize", dataStruct->qsize, &(dataStruct->qsize), "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", dataStruct->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", dataStruct->file1, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file2", dataStruct->file2, "INITIAL-STATE");
                tracepoint(stonesoup_trace, trace_point, "Spawning threads.");
                if (pthread_create(&stonesoup_t0, NULL, calcIncamount, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 0.");
                }
                if (pthread_create(&stonesoup_t1, NULL, toPound, (void*)(dataStruct)) != 0) {
                    stonesoup_printf("Error initializing thread 1.");
                }
                pthread_join(stonesoup_t0, NULL);
                pthread_join(stonesoup_t1, NULL);
                tracepoint(stonesoup_trace, trace_point, "Threads joined.");
            }
            free(dataStruct->data);
        } else {
                tracepoint(stonesoup_trace, trace_error, "Error parsing data.");
                stonesoup_printf("Error parsing data.\n");
        }
        free (dataStruct);
    } else {
        tracepoint(stonesoup_trace, trace_error, "Error malloc()ing space for struct.");
        stonesoup_printf("Error malloc()ing space for struct.\n");
    }
    tracepoint(stonesoup_trace, weakness_end);
;
stonesoup_close_printf_context();
}