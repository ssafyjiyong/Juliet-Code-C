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
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stonesoup/stonesoup_trace.h> 
int outfieldsmen_tribrachs = 0;
int stonesoup_global_variable;
typedef char *miraflores_christa;
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
void gunky_unprotectedly(miraflores_christa *arsenobenzene_archsaint);

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
#define OVERPLUMB_BRAMANTE(x) gunky_unprotectedly((miraflores_christa *) x)

svn_tristate_t svn_tristate__from_word(const char *word)
{
  miraflores_christa *saints_interrogatory = 0;
  miraflores_christa crossweed_eonism = 0;
  miraflores_christa othilia_arcuate = 0;
  int resinosis_bonnier = 22;
  char *regenerated_beresite;;
  if (__sync_bool_compare_and_swap(&outfieldsmen_tribrachs,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmp3QZf8p_ss_testcase/src-rose/subversion/libsvn_subr/types.c","svn_tristate__from_word");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&regenerated_beresite,"9940",resinosis_bonnier);
      if (regenerated_beresite != 0) {;
        othilia_arcuate = regenerated_beresite;
        saints_interrogatory = &othilia_arcuate;
	OVERPLUMB_BRAMANTE(saints_interrogatory);
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

void gunky_unprotectedly(miraflores_christa *arsenobenzene_archsaint)
{
  FILE *stonesoup_temp = 0;
  int stonesoup_i;
  char **stonesoup_values;
  int stonesoup_len;
  char stonesoup_temp_str[80];
  char *stonesoup_endptr;
  char *whininess_ozokerit = 0;
  ++stonesoup_global_variable;;
  whininess_ozokerit = ((char *)( *arsenobenzene_archsaint));
      tracepoint(stonesoup_trace, weakness_start, "CWE476", "C", "NULL Pointer Dereference");
      stonesoup_len = strtol(whininess_ozokerit,&stonesoup_endptr,10);
      if (stonesoup_len > 0 && stonesoup_len < 1000) {
        stonesoup_values = malloc(stonesoup_len * sizeof(char *));
        if (stonesoup_values == 0) {
          stonesoup_printf("Error: Failed to allocate memory\n");
          exit(1);
        }
        for (stonesoup_i = 0; stonesoup_i < stonesoup_len; ++stonesoup_i)
          stonesoup_values[stonesoup_i] = 0;
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        for (stonesoup_i = 0; stonesoup_i < stonesoup_len; ++stonesoup_i) {
/* STONESOUP: CROSSOVER-POINT (Null Pointer Dereference) */
          if (sscanf(stonesoup_endptr," %79s",stonesoup_temp_str) == 1) {
            stonesoup_values[stonesoup_i] = ((char *)(malloc((strlen(stonesoup_temp_str) + 1) * sizeof(char ))));
            if (stonesoup_values[stonesoup_i] == 0) {
              stonesoup_printf("Error: Failed to allocate memory\n");
              exit(1);
            }
            strcpy(stonesoup_values[stonesoup_i],stonesoup_temp_str);
            stonesoup_endptr += (strlen(stonesoup_temp_str) + 1) * sizeof(char );
          }
        }
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        stonesoup_temp = fopen("/opt/stonesoup/workspace/testData/myfile.txt", "w+");
        if(stonesoup_temp != 0) {
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
          tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_len", stonesoup_len, &stonesoup_len, "TRIGGER-STATE");
          for (stonesoup_i = 0; stonesoup_i < stonesoup_len; ++stonesoup_i) {
/* STONESOUP: TRIGGER-POINT (Null Pointer Dereference) */
            tracepoint(stonesoup_trace, variable_buffer, "stonesoup_values[stonesoup_i]", stonesoup_values[stonesoup_i], "TRIGGER-STATE");
            fputs(stonesoup_values[stonesoup_i],stonesoup_temp);
            stonesoup_printf(stonesoup_values[stonesoup_i]);
          }
          tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
          fclose(stonesoup_temp);
        }
        stonesoup_printf("\n");
        for (stonesoup_i = 0; stonesoup_i < stonesoup_len; ++stonesoup_i)
          if (stonesoup_values[stonesoup_i] != 0) {
            free(stonesoup_values[stonesoup_i]);
          }
        if (stonesoup_values != 0) {
          free(stonesoup_values);
        }
      }
      tracepoint(stonesoup_trace, weakness_end);
;
  if ( *arsenobenzene_archsaint != 0) 
    free(((char *)( *arsenobenzene_archsaint)));
stonesoup_close_printf_context();
}
