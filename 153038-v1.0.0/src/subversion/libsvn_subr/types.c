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
#include <stdarg.h> 
#include <stonesoup/stonesoup_trace.h> 
int fiertz_motteo = 0;
int stonesoup_global_variable;
typedef char *retackle_argulus;
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
void misdividing_throop(int calvadoses_unparcelled,... );
void formagenic_semanteme(retackle_argulus dracocephalum_anthophora);
void unenthroned_unwasted(retackle_argulus speakableness_mycetological);
void savorless_sweetens(retackle_argulus stalkiest_overtarry);
void miyasawa_footle(retackle_argulus unrealised_electrometry);
void odon_marilyn(retackle_argulus readopt_mayweed);
void cardiidae_sternutatory(retackle_argulus blowfishes_kirmanshah);
void downlink_brucellas(retackle_argulus mapes_colchester);
void hordeiform_retenue(retackle_argulus ichthyosaurus_geminiani);
void dramatization_hershell(retackle_argulus treblet_seeland);
void aornis_vorticella(retackle_argulus trikeria_guiding);
void cholecystalgia_billy(retackle_argulus sarcolemma_antemural);
void soricidae_podocarpous(retackle_argulus riverweed_kapfenberg);
void secchi_flavorlessness(retackle_argulus foss_genny);
void semifiction_resprout(retackle_argulus shrives_etalons);
void chimbleys_vantages(retackle_argulus dreamers_disavowed);
void refashioned_matthyas(retackle_argulus mucin_unforgetful);
void pantochrome_definite(retackle_argulus osteosarcoma_dictated);
void jading_penhead(retackle_argulus misassertion_orchil);
void outtongue_kiaat(retackle_argulus gnat_misuses);
void depew_butled(retackle_argulus cully_sped);
void pentelic_cycadlike(retackle_argulus kloman_unsaccharine);
void decarnate_stridulation(retackle_argulus noneffeteness_climatography);
void whitehead_hernsew(retackle_argulus nutramin_kodakry);
void bonina_hepatizing(retackle_argulus macklike_glennville);
void ungodly_cyp(retackle_argulus idiosepiidae_digital);
void epistasies_unadjacently(retackle_argulus squirearch_largeous);
void nestable_annunciable(retackle_argulus cisele_sinopic);
void yeeuch_nonmeteoric(retackle_argulus reargument_actionizing);
void triuridaceae_rifledom(retackle_argulus organosol_anorthosite);
void terpane_inevidence(retackle_argulus vineburg_thorpe);
void borgh_outsettler(retackle_argulus ingeniary_preataxic);
void calodemon_hartke(retackle_argulus anserous_pontormo);
void hornito_sereins(retackle_argulus plumbaginaceae_unwhistled);
void outboards_pechora(retackle_argulus frosty_mike);
void shrier_undebased(retackle_argulus superarbitrary_semicircularly);
void safranine_festucine(retackle_argulus beryllonite_dilatometry);
void graveolent_mucinous(retackle_argulus preadore_didymoid);
void extradural_zanana(retackle_argulus murshid_resuscitation);
void condensability_hafted(retackle_argulus retrochoir_avm);
void etwite_cephalology(retackle_argulus hydropult_pridefully);
void vacationists_teutonized(retackle_argulus unkindlier_bochum);
void lugones_resnatron(retackle_argulus oleo_fineer);
void inconformable_merkin(retackle_argulus allbee_overdilute);
void collectability_inhumanism(retackle_argulus kinetomeric_entre);
void quinate_minta(retackle_argulus osculant_stampsman);
void cootfoot_crotonic(retackle_argulus obligation_aedicule);
void gawish_simnelwise(retackle_argulus rebronze_sadhearted);
void neverthelater_overcomplicates(retackle_argulus hyperpurist_saigas);
void residua_volvet(retackle_argulus unclasped_hawks);
void soldadoes_debugs(retackle_argulus shieldtail_inthrone);
int stonesoup_single_global_variable = 0;
int stonesoup_canary_function_1()
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpBgpcf2_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_canary_function_1");
  ++stonesoup_single_global_variable;
  return 1;
}
int stonesoup_canary_function_2()
{
  tracepoint(stonesoup_trace, trace_location, "/tmp/tmpBgpcf2_ss_testcase/src-rose/subversion/libsvn_subr/types.c", "stonesoup_canary_function_2");
  ++stonesoup_single_global_variable;
  return 2;
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
  retackle_argulus preobject_chinwag = 0;
  int lithographer_pastorali = 19;
  char *autoerotically_exegetist;;
  if (__sync_bool_compare_and_swap(&fiertz_motteo,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpBgpcf2_ss_testcase/src-rose/subversion/libsvn_subr/types.c","svn_tristate__from_word");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&autoerotically_exegetist,"5660",lithographer_pastorali);
      if (autoerotically_exegetist != 0) {;
        preobject_chinwag = autoerotically_exegetist;
        misdividing_throop(1,preobject_chinwag);
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

void misdividing_throop(int calvadoses_unparcelled,... )
{
  retackle_argulus scottsboro_relicensing = 0;
  va_list unsalty_sequoia;
  ++stonesoup_global_variable;;
  if (calvadoses_unparcelled > 0) {
    __builtin_va_start(unsalty_sequoia,calvadoses_unparcelled);
    scottsboro_relicensing = (va_arg(unsalty_sequoia,retackle_argulus ));
    __builtin_va_end(unsalty_sequoia);
  }
  formagenic_semanteme(scottsboro_relicensing);
}

void formagenic_semanteme(retackle_argulus dracocephalum_anthophora)
{
  ++stonesoup_global_variable;;
  unenthroned_unwasted(dracocephalum_anthophora);
}

void unenthroned_unwasted(retackle_argulus speakableness_mycetological)
{
  ++stonesoup_global_variable;;
  savorless_sweetens(speakableness_mycetological);
}

void savorless_sweetens(retackle_argulus stalkiest_overtarry)
{
  ++stonesoup_global_variable;;
  miyasawa_footle(stalkiest_overtarry);
}

void miyasawa_footle(retackle_argulus unrealised_electrometry)
{
  ++stonesoup_global_variable;;
  odon_marilyn(unrealised_electrometry);
}

void odon_marilyn(retackle_argulus readopt_mayweed)
{
  ++stonesoup_global_variable;;
  cardiidae_sternutatory(readopt_mayweed);
}

void cardiidae_sternutatory(retackle_argulus blowfishes_kirmanshah)
{
  ++stonesoup_global_variable;;
  downlink_brucellas(blowfishes_kirmanshah);
}

void downlink_brucellas(retackle_argulus mapes_colchester)
{
  ++stonesoup_global_variable;;
  hordeiform_retenue(mapes_colchester);
}

void hordeiform_retenue(retackle_argulus ichthyosaurus_geminiani)
{
  ++stonesoup_global_variable;;
  dramatization_hershell(ichthyosaurus_geminiani);
}

void dramatization_hershell(retackle_argulus treblet_seeland)
{
  ++stonesoup_global_variable;;
  aornis_vorticella(treblet_seeland);
}

void aornis_vorticella(retackle_argulus trikeria_guiding)
{
  ++stonesoup_global_variable;;
  cholecystalgia_billy(trikeria_guiding);
}

void cholecystalgia_billy(retackle_argulus sarcolemma_antemural)
{
  ++stonesoup_global_variable;;
  soricidae_podocarpous(sarcolemma_antemural);
}

void soricidae_podocarpous(retackle_argulus riverweed_kapfenberg)
{
  ++stonesoup_global_variable;;
  secchi_flavorlessness(riverweed_kapfenberg);
}

void secchi_flavorlessness(retackle_argulus foss_genny)
{
  ++stonesoup_global_variable;;
  semifiction_resprout(foss_genny);
}

void semifiction_resprout(retackle_argulus shrives_etalons)
{
  ++stonesoup_global_variable;;
  chimbleys_vantages(shrives_etalons);
}

void chimbleys_vantages(retackle_argulus dreamers_disavowed)
{
  ++stonesoup_global_variable;;
  refashioned_matthyas(dreamers_disavowed);
}

void refashioned_matthyas(retackle_argulus mucin_unforgetful)
{
  ++stonesoup_global_variable;;
  pantochrome_definite(mucin_unforgetful);
}

void pantochrome_definite(retackle_argulus osteosarcoma_dictated)
{
  ++stonesoup_global_variable;;
  jading_penhead(osteosarcoma_dictated);
}

void jading_penhead(retackle_argulus misassertion_orchil)
{
  ++stonesoup_global_variable;;
  outtongue_kiaat(misassertion_orchil);
}

void outtongue_kiaat(retackle_argulus gnat_misuses)
{
  ++stonesoup_global_variable;;
  depew_butled(gnat_misuses);
}

void depew_butled(retackle_argulus cully_sped)
{
  ++stonesoup_global_variable;;
  pentelic_cycadlike(cully_sped);
}

void pentelic_cycadlike(retackle_argulus kloman_unsaccharine)
{
  ++stonesoup_global_variable;;
  decarnate_stridulation(kloman_unsaccharine);
}

void decarnate_stridulation(retackle_argulus noneffeteness_climatography)
{
  ++stonesoup_global_variable;;
  whitehead_hernsew(noneffeteness_climatography);
}

void whitehead_hernsew(retackle_argulus nutramin_kodakry)
{
  ++stonesoup_global_variable;;
  bonina_hepatizing(nutramin_kodakry);
}

void bonina_hepatizing(retackle_argulus macklike_glennville)
{
  ++stonesoup_global_variable;;
  ungodly_cyp(macklike_glennville);
}

void ungodly_cyp(retackle_argulus idiosepiidae_digital)
{
  ++stonesoup_global_variable;;
  epistasies_unadjacently(idiosepiidae_digital);
}

void epistasies_unadjacently(retackle_argulus squirearch_largeous)
{
  ++stonesoup_global_variable;;
  nestable_annunciable(squirearch_largeous);
}

void nestable_annunciable(retackle_argulus cisele_sinopic)
{
  ++stonesoup_global_variable;;
  yeeuch_nonmeteoric(cisele_sinopic);
}

void yeeuch_nonmeteoric(retackle_argulus reargument_actionizing)
{
  ++stonesoup_global_variable;;
  triuridaceae_rifledom(reargument_actionizing);
}

void triuridaceae_rifledom(retackle_argulus organosol_anorthosite)
{
  ++stonesoup_global_variable;;
  terpane_inevidence(organosol_anorthosite);
}

void terpane_inevidence(retackle_argulus vineburg_thorpe)
{
  ++stonesoup_global_variable;;
  borgh_outsettler(vineburg_thorpe);
}

void borgh_outsettler(retackle_argulus ingeniary_preataxic)
{
  ++stonesoup_global_variable;;
  calodemon_hartke(ingeniary_preataxic);
}

void calodemon_hartke(retackle_argulus anserous_pontormo)
{
  ++stonesoup_global_variable;;
  hornito_sereins(anserous_pontormo);
}

void hornito_sereins(retackle_argulus plumbaginaceae_unwhistled)
{
  ++stonesoup_global_variable;;
  outboards_pechora(plumbaginaceae_unwhistled);
}

void outboards_pechora(retackle_argulus frosty_mike)
{
  ++stonesoup_global_variable;;
  shrier_undebased(frosty_mike);
}

void shrier_undebased(retackle_argulus superarbitrary_semicircularly)
{
  ++stonesoup_global_variable;;
  safranine_festucine(superarbitrary_semicircularly);
}

void safranine_festucine(retackle_argulus beryllonite_dilatometry)
{
  ++stonesoup_global_variable;;
  graveolent_mucinous(beryllonite_dilatometry);
}

void graveolent_mucinous(retackle_argulus preadore_didymoid)
{
  ++stonesoup_global_variable;;
  extradural_zanana(preadore_didymoid);
}

void extradural_zanana(retackle_argulus murshid_resuscitation)
{
  ++stonesoup_global_variable;;
  condensability_hafted(murshid_resuscitation);
}

void condensability_hafted(retackle_argulus retrochoir_avm)
{
  ++stonesoup_global_variable;;
  etwite_cephalology(retrochoir_avm);
}

void etwite_cephalology(retackle_argulus hydropult_pridefully)
{
  ++stonesoup_global_variable;;
  vacationists_teutonized(hydropult_pridefully);
}

void vacationists_teutonized(retackle_argulus unkindlier_bochum)
{
  ++stonesoup_global_variable;;
  lugones_resnatron(unkindlier_bochum);
}

void lugones_resnatron(retackle_argulus oleo_fineer)
{
  ++stonesoup_global_variable;;
  inconformable_merkin(oleo_fineer);
}

void inconformable_merkin(retackle_argulus allbee_overdilute)
{
  ++stonesoup_global_variable;;
  collectability_inhumanism(allbee_overdilute);
}

void collectability_inhumanism(retackle_argulus kinetomeric_entre)
{
  ++stonesoup_global_variable;;
  quinate_minta(kinetomeric_entre);
}

void quinate_minta(retackle_argulus osculant_stampsman)
{
  ++stonesoup_global_variable;;
  cootfoot_crotonic(osculant_stampsman);
}

void cootfoot_crotonic(retackle_argulus obligation_aedicule)
{
  ++stonesoup_global_variable;;
  gawish_simnelwise(obligation_aedicule);
}

void gawish_simnelwise(retackle_argulus rebronze_sadhearted)
{
  ++stonesoup_global_variable;;
  neverthelater_overcomplicates(rebronze_sadhearted);
}

void neverthelater_overcomplicates(retackle_argulus hyperpurist_saigas)
{
  ++stonesoup_global_variable;;
  residua_volvet(hyperpurist_saigas);
}

void residua_volvet(retackle_argulus unclasped_hawks)
{
  ++stonesoup_global_variable;;
  soldadoes_debugs(unclasped_hawks);
}

void soldadoes_debugs(retackle_argulus shieldtail_inthrone)
{
    int stonesoup_i = 0;
    int stonesoup_index;
    int (*stonesoup_after_ptr[1])();
    unsigned char stonesoup_count[62];
    int (*stonesoup_before_ptr[1])();
    char stonesoup_str_buf[40] = {0};
  char *pedes_deadpan = 0;
  ++stonesoup_global_variable;;
  pedes_deadpan = ((char *)shieldtail_inthrone);
    tracepoint(stonesoup_trace, weakness_start, "CWE129", "A", "Improper Validation of Array Index");
    strncpy(stonesoup_str_buf,pedes_deadpan,39);
    stonesoup_str_buf[39] = 0;
    for (stonesoup_i = 0; stonesoup_i < 62; stonesoup_i++) {
        stonesoup_count[stonesoup_i] = 0;
    }
    if (strlen(stonesoup_str_buf) > 1 && stonesoup_str_buf[0] > 'a') {
        stonesoup_before_ptr[0] = stonesoup_canary_function_1;
        stonesoup_after_ptr[0] = stonesoup_canary_function_1;
    }
    else {
        stonesoup_before_ptr[0] = stonesoup_canary_function_2;
        stonesoup_after_ptr[0] = stonesoup_canary_function_2;
    }
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    for (stonesoup_i = 0; stonesoup_i < strlen(stonesoup_str_buf); stonesoup_i++)
        /* STONESOUP: CROSSOVER-POINT (Improper Validation of Array Index) */
        /* STONESOUP: TRIGGER-POINT (Improper Validation of Array Index: Ascii Bounds) */
    {
        if (stonesoup_str_buf[stonesoup_i] > 96) {
            stonesoup_index = stonesoup_str_buf[stonesoup_i] - 'a' + 36;
            if (stonesoup_count[stonesoup_index] < 255)
                stonesoup_count[stonesoup_index]++;
        }
        else if (stonesoup_str_buf[stonesoup_i] < 58) {
            stonesoup_index = stonesoup_str_buf[stonesoup_i] - 48;
            tracepoint(stonesoup_trace, variable_signed_integral, "stonesoup_index", stonesoup_index, &stonesoup_index, "TRIGGER-POINT");
            if (stonesoup_count[stonesoup_index] < 255)
                stonesoup_count[stonesoup_index]++;
        }
        else {
            stonesoup_index = stonesoup_str_buf[stonesoup_i] - 'A' + 10;
            if (stonesoup_count[stonesoup_index] < 255)
                stonesoup_count[stonesoup_index]++;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
    for (stonesoup_i = 0; stonesoup_i < 62; stonesoup_i++) {
        stonesoup_printf("index %d: %d\n",stonesoup_i,stonesoup_count[stonesoup_i]);
    }
    stonesoup_printf("%d\n",stonesoup_before_ptr[0]());
    stonesoup_printf("%d\n",stonesoup_after_ptr[0]());
    tracepoint(stonesoup_trace, weakness_end);
;
  if (shieldtail_inthrone != 0) 
    free(((char *)shieldtail_inthrone));
stonesoup_close_printf_context();
}
