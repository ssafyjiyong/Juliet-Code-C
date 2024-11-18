/*
 * config.c :  reading configuration information
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
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include <apr_want.h>
#include <apr_general.h>
#include <apr_lib.h>
#include "svn_hash.h"
#include "svn_error.h"
#include "svn_pools.h"
#include "config_impl.h"
#include "svn_private_config.h"
#include "private/svn_dep_compat.h"
/* Section table entries. */
#include <sys/stat.h> 
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <stonesoup/stonesoup_trace.h> 
struct cfg_section_t ;
typedef struct cfg_section_t cfg_section_t;

struct cfg_section_t 
{
/* The section name. */
  const char *name;
/* Table of cfg_option_t's. */
  apr_hash_t *options;
}
;
/* Option table entries. */
struct cfg_option_t ;
typedef struct cfg_option_t cfg_option_t;

struct cfg_option_t 
{
/* The option name. */
  const char *name;
/* The option name, converted into a hash key. */
  const char *hash_key;
/* The unexpanded option value. */
  const char *value;
/* The expanded option value. */
  const char *x_value;
/* Expansion flag. If this is TRUE, this value has already been expanded.
     In this case, if x_value is NULL, no expansions were necessary,
     and value should be used directly. */
  svn_boolean_t expanded;
}
;
int ongun_unornate = 0;
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
void respiratored_softheadedly(char **flensing_perpetuality);
void prosthetist_minar(char **leukons_aftertask);
void stimulating_independista(char **recipiangle_aphonia);
void spikers_simonov(char **murshid_crossett);
void tammock_fountaineer(char **plashingly_federalising);
void phagolytic_smeer(char **everhart_avelina);
void ochelata_magbie(char **inquiries_coursey);
void protoxylem_partlet(char **preobligation_saxaul);
void helda_acylated(char **optimate_auliffe);
void suprapedal_overhappiness(char **grandmothers_darkness);
void resurrects_hypoendocrinism(char **gervais_extollation);
void candyh_shenstone(char **twiers_despondencies);
void trollyman_nonfrugally(char **hierogram_centrechinoida);
void unproliferous_postmediastinal(char **hagship_collielike);
void bulak_palmyra(char **arterializing_marocain);
void paragram_koda(char **allegheny_arsonium);
void serenata_coevolving(char **amphibiontic_thoracal);
void polo_speccing(char **binalonen_aerophobic);
void quadruplicating_nonentities(char **scolloped_leannesses);
void embryogenetic_unprematureness(char **political_autobus);
void obcompressed_friends(char **unacquaintable_divulsive);
void nonuniversality_brum(char **griggles_temporization);
void boyars_underturf(char **weened_mislaid);
void tatterly_grousers(char **chirocosmetics_hobbledehoys);
void foyaite_rachial(char **agists_crimini);
void zoodynamic_uncircuitously(char **immetricalness_beaupere);
void forgery_eschalots(char **outtalked_completes);
void plicae_preparingly(char **craftsperson_schatz);
void orwell_unhoaxability(char **citramontane_shandry);
void selenous_laniinae(char **tagbanua_noddingly);
void proditorious_knifeproof(char **eclosions_nickstick);
void thromboplastic_emlynne(char **cusp_rome);
void trockery_flannelmouth(char **bighorns_nationals);
void feller_sequentialized(char **preconcept_mutagenicity);
void suasion_sperable(char **untoxically_nimming);
void gylden_cephei(char **nanoid_ultroneously);
void wagedom_wrest(char **cleanlinesses_exigeant);
void bilharziasis_relucts(char **superperson_nuzzles);
void succulous_abiogenetical(char **osteoid_higbee);
void lordships_dissavs(char **cameralism_javelina);
void furnaceman_sigmaspire(char **zattare_humourize);
void aotearoa_lucite(char **caroled_offerer);
void paratrophy_ceraunite(char **ulmin_dighton);
void furfurylidene_overstress(char **gammers_cardiidae);
void respectworthy_outpoise(char **historians_seders);
void cardon_nonallotment(char **dodds_plantation);
void mazing_lindsey(char **aulical_creedless);
void tush_babelish(char **posterishness_unstrapping);
void paye_gudea(char **preimmunizing_bacitracin);
void cunaxa_mishandling(char **polypeptide_boozily);

svn_error_t *svn_config_create2(svn_config_t **cfgp,svn_boolean_t section_names_case_sensitive,svn_boolean_t option_names_case_sensitive,apr_pool_t *result_pool)
{
  svn_config_t *cfg = (apr_palloc(result_pool,sizeof(( *cfg))));
  cfg -> sections = apr_hash_make(result_pool);
  cfg -> pool = result_pool;
  cfg -> x_pool = svn_pool_create_ex(result_pool,((void *)0));
  cfg -> x_values = 0;
  cfg -> tmp_key = svn_stringbuf_create_empty(result_pool);
  cfg -> tmp_value = svn_stringbuf_create_empty(result_pool);
  cfg -> section_names_case_sensitive = section_names_case_sensitive;
  cfg -> option_names_case_sensitive = option_names_case_sensitive;
   *cfgp = cfg;
  return 0;
}

svn_error_t *svn_config_read3(svn_config_t **cfgp,const char *file,svn_boolean_t must_exist,svn_boolean_t section_names_case_sensitive,svn_boolean_t option_names_case_sensitive,apr_pool_t *result_pool)
{
  char **rattery_utilizing = 0;
  long salvational_majolica[10];
  char **waterloggedness_hargeisa[10] = {0};
  char *abstinence_orbier[48] = {0};
  int minify_headfishes = 29;
  char *tamaqua_millioersted;
  svn_config_t *cfg;
  svn_error_t *err;
  if (__sync_bool_compare_and_swap(&ongun_unornate,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpNRZfAd_ss_testcase/src-rose/subversion/libsvn_subr/config.c","svn_config_read3");
      stonesoup_setup_printf_context();
      stonesoup_read_taint(&tamaqua_millioersted,"8007",minify_headfishes);
      if (tamaqua_millioersted != 0) {;
        abstinence_orbier[19] = tamaqua_millioersted;
        waterloggedness_hargeisa[5] = abstinence_orbier;
        salvational_majolica[1] = 5;
        rattery_utilizing =  *(waterloggedness_hargeisa + salvational_majolica[1]);
        respiratored_softheadedly(rattery_utilizing);
      }
    }
  }
  do {
    svn_error_t *svn_err__temp = svn_config_create2(&cfg,section_names_case_sensitive,option_names_case_sensitive,result_pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
/* Yes, this is platform-specific code in Subversion, but there's no
     practical way to migrate it into APR, as it's simultaneously
     Subversion-specific and Windows-specific.  Even if we eventually
     want to have APR offer a generic config-reading interface, it
     makes sense to test it here first and migrate it later. */
#ifdef WIN32
#endif /* WIN32 */
  err = svn_config__parse_file(cfg,file,must_exist,result_pool);
  if (err != 0) {
    return err;
  }
  else {
     *cfgp = cfg;
  }
  return 0;
}

svn_error_t *svn_config_parse(svn_config_t **cfgp,svn_stream_t *stream,svn_boolean_t section_names_case_sensitive,svn_boolean_t option_names_case_sensitive,apr_pool_t *result_pool)
{
  svn_config_t *cfg;
  svn_error_t *err;
  apr_pool_t *scratch_pool = svn_pool_create_ex(result_pool,((void *)0));
  err = svn_config_create2(&cfg,section_names_case_sensitive,option_names_case_sensitive,result_pool);
  if (err == 0) {
    err = svn_config__parse_stream(cfg,stream,result_pool,scratch_pool);
  }
  if (err == 0) {
     *cfgp = cfg;
  }
  apr_pool_destroy(scratch_pool);
  return err;
}
/* Read various configuration sources into *CFGP, in this order, with
 * later reads overriding the results of earlier ones:
 *
 *    1. SYS_REGISTRY_PATH   (only on Win32, but ignored if NULL)
 *
 *    2. SYS_FILE_PATH       (everywhere, but ignored if NULL)
 *
 *    3. USR_REGISTRY_PATH   (only on Win32, but ignored if NULL)
 *
 *    4. USR_FILE_PATH       (everywhere, but ignored if NULL)
 *
 * Allocate *CFGP in POOL.  Even if no configurations are read,
 * allocate an empty *CFGP.
 */

static svn_error_t *read_all(svn_config_t **cfgp,const char *sys_registry_path,const char *usr_registry_path,const char *sys_file_path,const char *usr_file_path,apr_pool_t *pool)
{
/* "red" is the past tense of "read" */
  svn_boolean_t red_config = 0;
/*** Read system-wide configurations first... ***/
#ifdef WIN32
#endif /* WIN32 */
  if (sys_file_path) {
    if (red_config) {
      do {
        svn_error_t *svn_err__temp = svn_config_merge( *cfgp,sys_file_path,0);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    else {
      do {
        svn_error_t *svn_err__temp = svn_config_read3(cfgp,sys_file_path,0,0,0,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
      red_config = !0;
    }
  }
/*** ...followed by per-user configurations. ***/
#ifdef WIN32
#endif /* WIN32 */
  if (usr_file_path) {
    if (red_config) {
      do {
        svn_error_t *svn_err__temp = svn_config_merge( *cfgp,usr_file_path,0);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
    }
    else {
      do {
        svn_error_t *svn_err__temp = svn_config_read3(cfgp,usr_file_path,0,0,0,pool);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
      red_config = !0;
    }
  }
  if (!red_config) {
    do {
      svn_error_t *svn_err__temp = svn_config_create2(cfgp,0,0,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
  }
  return 0;
}
/* CONFIG_DIR provides an override for the default behavior of reading
   the default set of overlay files described by read_all()'s doc
   string. */

static svn_error_t *get_category_config(svn_config_t **cfg,const char *config_dir,const char *category,apr_pool_t *pool)
{
  const char *usr_reg_path = ((void *)0);
  const char *sys_reg_path = ((void *)0);
  const char *usr_cfg_path;
  const char *sys_cfg_path;
  svn_error_t *err = ((void *)0);
   *cfg = ((void *)0);
  if (!config_dir) {
#ifdef WIN32
#endif /* WIN32 */
    err = svn_config__sys_config_path(&sys_cfg_path,category,pool);
    if (err && err -> apr_err == SVN_ERR_BAD_FILENAME) {
      sys_cfg_path = ((void *)0);
      svn_error_clear(err);
    }
    else {
      if (err) {
        return err;
      }
    }
  }
  else {
    sys_cfg_path = ((void *)0);
  }
  do {
    svn_error_t *svn_err__temp = svn_config_get_user_config_path(&usr_cfg_path,config_dir,category,pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  return read_all(cfg,sys_reg_path,usr_reg_path,sys_cfg_path,usr_cfg_path,pool);
}

svn_error_t *svn_config_get_config(apr_hash_t **cfg_hash,const char *config_dir,apr_pool_t *pool)
{
  svn_config_t *cfg;
   *cfg_hash = apr_hash_make(pool);
#define CATLEN (sizeof(SVN_CONFIG_CATEGORY_SERVERS) - 1)
  do {
    svn_error_t *svn_err__temp = get_category_config(&cfg,config_dir,"servers",pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  if (cfg) {
    apr_hash_set( *cfg_hash,"servers",(sizeof("servers") - 1),cfg);
  }
#undef CATLEN
#define CATLEN (sizeof(SVN_CONFIG_CATEGORY_CONFIG) - 1)
  do {
    svn_error_t *svn_err__temp = get_category_config(&cfg,config_dir,"config",pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  if (cfg) {
    apr_hash_set( *cfg_hash,"config",(sizeof("config") - 1),cfg);
  }
#undef CATLEN
  return 0;
}
/* Iterate through CFG, passing BATON to CALLBACK for every (SECTION, OPTION)
   pair.  Stop if CALLBACK returns TRUE.  Allocate from POOL. */

static void for_each_option(svn_config_t *cfg,void *baton,apr_pool_t *pool,svn_boolean_t callback(void *, cfg_section_t *, cfg_option_t *))
{
  apr_hash_index_t *sec_ndx;
  for (sec_ndx = apr_hash_first(pool,cfg -> sections); sec_ndx != ((void *)0); sec_ndx = apr_hash_next(sec_ndx)) {
    void *sec_ptr;
    cfg_section_t *sec;
    apr_hash_index_t *opt_ndx;
    apr_hash_this(sec_ndx,((void *)0),((void *)0),&sec_ptr);
    sec = sec_ptr;
    for (opt_ndx = apr_hash_first(pool,sec -> options); opt_ndx != ((void *)0); opt_ndx = apr_hash_next(opt_ndx)) {
      void *opt_ptr;
      cfg_option_t *opt;
      apr_hash_this(opt_ndx,((void *)0),((void *)0),&opt_ptr);
      opt = opt_ptr;
      if (callback(baton,sec,opt)) {
        return ;
      }
    }
  }
}

static svn_boolean_t merge_callback(void *baton,cfg_section_t *section,cfg_option_t *option)
{
  svn_config_set(baton,section -> name,option -> name,option -> value);
  return 0;
}

svn_error_t *svn_config_merge(svn_config_t *cfg,const char *file,svn_boolean_t must_exist)
{
/* The original config hash shouldn't change if there's an error
     while reading the confguration, so read into a temporary table.
     ### We could use a tmp subpool for this, since merge_cfg is going
     to be tossed afterwards.  Premature optimization, though? */
  svn_config_t *merge_cfg;
  do {
    svn_error_t *svn_err__temp = svn_config_read3(&merge_cfg,file,must_exist,cfg -> section_names_case_sensitive,cfg -> option_names_case_sensitive,cfg -> pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
/* Now copy the new options into the original table. */
  for_each_option(merge_cfg,cfg,merge_cfg -> pool,merge_callback);
  return 0;
}
/* Remove variable expansions from CFG.  Walk through the options tree,
   killing all expanded values, then clear the expanded value pool. */

static svn_boolean_t rmex_callback(void *baton,cfg_section_t *section,cfg_option_t *option)
{
/* Only clear the `expanded' flag if the value actually contains
     variable expansions. */
  if (option -> expanded && option -> x_value != ((void *)0)) {
    option -> x_value = ((void *)0);
    option -> expanded = 0;
  }
  return 0;
}

static void remove_expansions(svn_config_t *cfg)
{
  if (!cfg -> x_values) {
    return ;
  }
  for_each_option(cfg,((void *)0),cfg -> x_pool,rmex_callback);
  apr_pool_clear(cfg -> x_pool);
  cfg -> x_values = 0;
}
/* Canonicalize a string for hashing.  Modifies KEY in place. */

inline static char *make_hash_key(char *key)
{
  register char *p;
  for (p = key; ( *p) != 0; ++p) 
     *p = ((char )(tolower(((unsigned char )( *p)))));
  return key;
}
/* Return a pointer to an option in CFG, or NULL if it doesn't exist.
   if SECTIONP is non-null, return a pointer to the option's section.
   OPTION may be NULL. */

static cfg_option_t *find_option(svn_config_t *cfg,const char *section,const char *option,cfg_section_t **sectionp)
{
  void *sec_ptr;
/* Canonicalize the hash key */
  svn_stringbuf_set(cfg -> tmp_key,section);
  if (!cfg -> section_names_case_sensitive) {
    make_hash_key(cfg -> tmp_key -> data);
  }
  sec_ptr = apr_hash_get(cfg -> sections,(cfg -> tmp_key -> data),(cfg -> tmp_key -> len));
  if (sectionp != ((void *)0)) {
     *sectionp = sec_ptr;
  }
  if (sec_ptr != ((void *)0) && option != ((void *)0)) {
    cfg_section_t *sec = sec_ptr;
    cfg_option_t *opt;
/* Canonicalize the option key */
    svn_stringbuf_set(cfg -> tmp_key,option);
    if (!cfg -> option_names_case_sensitive) {
      make_hash_key(cfg -> tmp_key -> data);
    }
    opt = (apr_hash_get(sec -> options,(cfg -> tmp_key -> data),(cfg -> tmp_key -> len)));
/* NOTE: ConfigParser's sections are case sensitive. */
    if (opt == ((void *)0) && apr_strnatcasecmp(section,"DEFAULT") != 0) {
/* Options which aren't found in the requested section are
           also sought after in the default section. */
      opt = find_option(cfg,"DEFAULT",option,&sec);
    }
    return opt;
  }
  return ((void *)0);
}
/* Has a bi-directional dependency with make_string_from_option(). */
static void expand_option_value(svn_config_t *cfg,cfg_section_t *section,const char *opt_value,const char **opt_x_valuep,apr_pool_t *x_pool);
/* Set *VALUEP according to the OPT's value.  A value for X_POOL must
   only ever be passed into this function by expand_option_value(). */

static void make_string_from_option(const char **valuep,svn_config_t *cfg,cfg_section_t *section,cfg_option_t *opt,apr_pool_t *x_pool)
{
/* Expand the option value if necessary. */
  if (!opt -> expanded) {
/* before attempting to expand an option, check for the placeholder.
       * If none is there, there is no point in calling expand_option_value.
       */
    if (opt -> value && strchr(opt -> value,37)) {
      apr_pool_t *tmp_pool = x_pool?x_pool : svn_pool_create_ex(cfg -> x_pool,((void *)0));
      expand_option_value(cfg,section,opt -> value,&opt -> x_value,tmp_pool);
      opt -> expanded = !0;
      if (!x_pool) {
/* Grab the fully expanded value from tmp_pool before its
                 disappearing act. */
        if (opt -> x_value) {
          opt -> x_value = (apr_pstrmemdup(cfg -> x_pool,opt -> x_value,strlen(opt -> x_value)));
        }
        apr_pool_destroy(tmp_pool);
      }
    }
    else {
      opt -> expanded = !0;
    }
  }
  if (opt -> x_value) {
     *valuep = opt -> x_value;
  }
  else {
     *valuep = opt -> value;
  }
}
/* Start of variable-replacement placeholder */
#define FMT_START     "%("
#define FMT_START_LEN (sizeof(FMT_START) - 1)
/* End of variable-replacement placeholder */
#define FMT_END       ")s"
#define FMT_END_LEN   (sizeof(FMT_END) - 1)
/* Expand OPT_VALUE (which may be NULL) in SECTION into *OPT_X_VALUEP.
   If no variable replacements are done, set *OPT_X_VALUEP to
   NULL. Allocate from X_POOL. */

static void expand_option_value(svn_config_t *cfg,cfg_section_t *section,const char *opt_value,const char **opt_x_valuep,apr_pool_t *x_pool)
{
  svn_stringbuf_t *buf = ((void *)0);
  const char *parse_from = opt_value;
  const char *copy_from = parse_from;
  const char *name_start;
  const char *name_end;
  while(parse_from != ((void *)0) && ( *parse_from) != '\0' && (name_start = (strstr(parse_from,"%("))) != ((void *)0)){
    name_start += sizeof("%(") - 1;
    if (( *name_start) == '\0') {
/* FMT_START at end of opt_value. */
      break; 
    }
    name_end = (strstr(name_start,")s"));
    if (name_end != ((void *)0)) {
      cfg_option_t *x_opt;
      apr_size_t len = (name_end - name_start);
      char *name = apr_pstrmemdup(x_pool,name_start,len);
      x_opt = find_option(cfg,section -> name,name,((void *)0));
      if (x_opt != ((void *)0)) {
        const char *cstring;
/* Pass back the sub-pool originally provided by
                 make_string_from_option() as an indication of when it
                 should terminate. */
        make_string_from_option(&cstring,cfg,section,x_opt,x_pool);
/* Append the plain text preceding the expansion. */
        len = (name_start - (sizeof("%(") - 1) - copy_from);
        if (buf == ((void *)0)) {
          buf = svn_stringbuf_ncreate(copy_from,len,x_pool);
          cfg -> x_values = !0;
        }
        else {
          svn_stringbuf_appendbytes(buf,copy_from,len);
        }
/* Append the expansion and adjust parse pointers. */
        svn_stringbuf_appendcstr(buf,cstring);
        parse_from = name_end + (sizeof(")s") - 1);
        copy_from = parse_from;
      }
      else {
/* Though ConfigParser considers the failure to resolve
               the requested expansion an exception condition, we
               consider it to be plain text, and look for the start of
               the next one. */
        parse_from = name_end + (sizeof(")s") - 1);
      }
    }
    else {
/* Though ConfigParser treats unterminated format specifiers
           as an exception condition, we consider them to be plain
           text.  The fact that there are no more format specifier
           endings means we're done parsing. */
      parse_from = ((void *)0);
    }
  }
  if (buf != ((void *)0)) {
/* Copy the remainder of the plain text. */
    svn_stringbuf_appendcstr(buf,copy_from);
     *opt_x_valuep = (buf -> data);
  }
  else {
     *opt_x_valuep = ((void *)0);
  }
}

static cfg_section_t *svn_config_addsection(svn_config_t *cfg,const char *section)
{
  cfg_section_t *s;
  const char *hash_key;
  s = (apr_palloc(cfg -> pool,sizeof(cfg_section_t )));
  s -> name = (apr_pstrdup(cfg -> pool,section));
  if (cfg -> section_names_case_sensitive) {
    hash_key = s -> name;
  }
  else {
    hash_key = (make_hash_key(apr_pstrdup(cfg -> pool,section)));
  }
  s -> options = apr_hash_make(cfg -> pool);
  apr_hash_set(cfg -> sections,hash_key,(- 1),s);
  return s;
}

static void svn_config_create_option(cfg_option_t **opt,const char *option,const char *value,svn_boolean_t option_names_case_sensitive,apr_pool_t *pool)
{
  cfg_option_t *o;
  o = (apr_palloc(pool,sizeof(cfg_option_t )));
  o -> name = (apr_pstrdup(pool,option));
  if (option_names_case_sensitive) {
    o -> hash_key = o -> name;
  }
  else {
    o -> hash_key = (make_hash_key(apr_pstrdup(pool,option)));
  }
  o -> value = (apr_pstrdup(pool,value));
  o -> x_value = ((void *)0);
  o -> expanded = 0;
   *opt = o;
}

void svn_config_get(svn_config_t *cfg,const char **valuep,const char *section,const char *option,const char *default_value)
{
   *valuep = default_value;
  if (cfg) {
    cfg_section_t *sec;
    cfg_option_t *opt = find_option(cfg,section,option,&sec);
    if (opt != ((void *)0)) {
      make_string_from_option(valuep,cfg,sec,opt,((void *)0));
    }
    else {
/* before attempting to expand an option, check for the placeholder.
         * If none is there, there is no point in calling expand_option_value.
         */
      if (default_value && strchr(default_value,37)) {
        apr_pool_t *tmp_pool = svn_pool_create_ex(cfg -> x_pool,((void *)0));
        const char *x_default;
        expand_option_value(cfg,sec,default_value,&x_default,tmp_pool);
        if (x_default) {
          svn_stringbuf_set(cfg -> tmp_value,x_default);
           *valuep = (cfg -> tmp_value -> data);
        }
        apr_pool_destroy(tmp_pool);
      }
    }
  }
}

void svn_config_set(svn_config_t *cfg,const char *section,const char *option,const char *value)
{
  cfg_section_t *sec;
  cfg_option_t *opt;
  remove_expansions(cfg);
  opt = find_option(cfg,section,option,&sec);
  if (opt != ((void *)0)) {
/* Replace the option's value. */
    opt -> value = (apr_pstrdup(cfg -> pool,value));
    opt -> expanded = 0;
    return ;
  }
/* Create a new option */
  svn_config_create_option(&opt,option,value,cfg -> option_names_case_sensitive,cfg -> pool);
  if (sec == ((void *)0)) {
/* Even the section doesn't exist. Create it. */
    sec = svn_config_addsection(cfg,section);
  }
  apr_hash_set(sec -> options,(opt -> hash_key),(- 1),opt);
}
/* Set *BOOLP to true or false depending (case-insensitively) on INPUT.
   If INPUT is null, set *BOOLP to DEFAULT_VALUE.
   INPUT is a string indicating truth or falsehood in any of the usual
   ways: "true"/"yes"/"on"/etc, "false"/"no"/"off"/etc.
   If INPUT is neither NULL nor a recognized string, return an error
   with code SVN_ERR_BAD_CONFIG_VALUE; use SECTION and OPTION in
   constructing the error string. */

static svn_error_t *get_bool(svn_boolean_t *boolp,const char *input,svn_boolean_t default_value,const char *section,const char *option)
{
  svn_tristate_t value = svn_tristate__from_word(input);
  if (value == svn_tristate_true) {
     *boolp = !0;
  }
  else {
    if (value == svn_tristate_false) {
       *boolp = 0;
    }
    else {
/* no value provided */
      if (input == ((void *)0)) {
         *boolp = default_value;
      }
      else {
/* unrecognized value */
        if (section) {
          return svn_error_createf(SVN_ERR_BAD_CONFIG_VALUE,((void *)0),(dgettext("subversion","Config error: invalid boolean value '%s' for '[%s] %s'")),input,section,option);
        }
        else {
          return svn_error_createf(SVN_ERR_BAD_CONFIG_VALUE,((void *)0),(dgettext("subversion","Config error: invalid boolean value '%s' for '%s'")),input,option);
        }
      }
    }
  }
  return 0;
}

svn_error_t *svn_config_get_bool(svn_config_t *cfg,svn_boolean_t *valuep,const char *section,const char *option,svn_boolean_t default_value)
{
  const char *tmp_value;
  svn_config_get(cfg,&tmp_value,section,option,((void *)0));
  return get_bool(valuep,tmp_value,default_value,section,option);
}

void svn_config_set_bool(svn_config_t *cfg,const char *section,const char *option,svn_boolean_t value)
{
  svn_config_set(cfg,section,option,(value?"TRUE" : "FALSE"));
}

svn_error_t *svn_config_get_int64(svn_config_t *cfg,apr_int64_t *valuep,const char *section,const char *option,apr_int64_t default_value)
{
  const char *tmp_value;
  svn_config_get(cfg,&tmp_value,section,option,((void *)0));
  if (tmp_value) {
    return svn_cstring_strtoi64(valuep,tmp_value,- 9223372036854775807L - 1,9223372036854775807L,10);
  }
   *valuep = default_value;
  return 0;
}

void svn_config_set_int64(svn_config_t *cfg,const char *section,const char *option,apr_int64_t value)
{
  svn_config_set(cfg,section,option,(apr_psprintf(cfg -> pool,"%ld",value)));
}

svn_error_t *svn_config_get_yes_no_ask(svn_config_t *cfg,const char **valuep,const char *section,const char *option,const char *default_value)
{
  const char *tmp_value;
  svn_config_get(cfg,&tmp_value,section,option,((void *)0));
  if (!tmp_value) {
    tmp_value = default_value;
  }
  if (tmp_value && 0 == svn_cstring_casecmp(tmp_value,"ASK")) {
     *valuep = "ASK";
  }
  else {
    svn_boolean_t bool_val;
/* We already incorporated default_value into tmp_value if
         necessary, so the FALSE below will be ignored unless the
         caller is doing something it shouldn't be doing. */
    do {
      svn_error_t *svn_err__temp = get_bool(&bool_val,tmp_value,0,section,option);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
     *valuep = ((bool_val?"TRUE" : "FALSE"));
  }
  return 0;
}

svn_error_t *svn_config_get_tristate(svn_config_t *cfg,svn_tristate_t *valuep,const char *section,const char *option,const char *unknown_value,svn_tristate_t default_value)
{
  const char *tmp_value;
  svn_config_get(cfg,&tmp_value,section,option,((void *)0));
  if (!tmp_value) {
     *valuep = default_value;
  }
  else {
    if (0 == svn_cstring_casecmp(tmp_value,unknown_value)) {
       *valuep = svn_tristate_unknown;
    }
    else {
      svn_boolean_t bool_val;
/* We already incorporated default_value into tmp_value if
         necessary, so the FALSE below will be ignored unless the
         caller is doing something it shouldn't be doing. */
      do {
        svn_error_t *svn_err__temp = get_bool(&bool_val,tmp_value,0,section,option);
        if (svn_err__temp) {
          return svn_err__temp;
        }
      }while (0);
       *valuep = ((bool_val?svn_tristate_true : svn_tristate_false));
    }
  }
  return 0;
}

int svn_config_enumerate_sections(svn_config_t *cfg,svn_config_section_enumerator_t callback,void *baton)
{
  apr_hash_index_t *sec_ndx;
  int count = 0;
  apr_pool_t *subpool = svn_pool_create_ex(cfg -> x_pool,((void *)0));
  for (sec_ndx = apr_hash_first(subpool,cfg -> sections); sec_ndx != ((void *)0); sec_ndx = apr_hash_next(sec_ndx)) {
    void *sec_ptr;
    cfg_section_t *sec;
    apr_hash_this(sec_ndx,((void *)0),((void *)0),&sec_ptr);
    sec = sec_ptr;
    ++count;
    if (!callback(sec -> name,baton)) {
      break; 
    }
  }
  apr_pool_destroy(subpool);
  return count;
}

int svn_config_enumerate_sections2(svn_config_t *cfg,svn_config_section_enumerator2_t callback,void *baton,apr_pool_t *pool)
{
  apr_hash_index_t *sec_ndx;
  apr_pool_t *iteration_pool;
  int count = 0;
  iteration_pool = svn_pool_create_ex(pool,((void *)0));
  for (sec_ndx = apr_hash_first(pool,cfg -> sections); sec_ndx != ((void *)0); sec_ndx = apr_hash_next(sec_ndx)) {
    void *sec_ptr;
    cfg_section_t *sec;
    apr_hash_this(sec_ndx,((void *)0),((void *)0),&sec_ptr);
    sec = sec_ptr;
    ++count;
    apr_pool_clear(iteration_pool);
    if (!callback(sec -> name,baton,iteration_pool)) {
      break; 
    }
  }
  apr_pool_destroy(iteration_pool);
  return count;
}

int svn_config_enumerate(svn_config_t *cfg,const char *section,svn_config_enumerator_t callback,void *baton)
{
  cfg_section_t *sec;
  apr_hash_index_t *opt_ndx;
  int count;
  apr_pool_t *subpool;
  find_option(cfg,section,((void *)0),&sec);
  if (sec == ((void *)0)) {
    return 0;
  }
  subpool = svn_pool_create_ex(cfg -> x_pool,((void *)0));
  count = 0;
  for (opt_ndx = apr_hash_first(subpool,sec -> options); opt_ndx != ((void *)0); opt_ndx = apr_hash_next(opt_ndx)) {
    void *opt_ptr;
    cfg_option_t *opt;
    const char *temp_value;
    apr_hash_this(opt_ndx,((void *)0),((void *)0),&opt_ptr);
    opt = opt_ptr;
    ++count;
    make_string_from_option(&temp_value,cfg,sec,opt,((void *)0));
    if (!callback(opt -> name,temp_value,baton)) {
      break; 
    }
  }
  apr_pool_destroy(subpool);
  return count;
}

int svn_config_enumerate2(svn_config_t *cfg,const char *section,svn_config_enumerator2_t callback,void *baton,apr_pool_t *pool)
{
  cfg_section_t *sec;
  apr_hash_index_t *opt_ndx;
  apr_pool_t *iteration_pool;
  int count;
  find_option(cfg,section,((void *)0),&sec);
  if (sec == ((void *)0)) {
    return 0;
  }
  iteration_pool = svn_pool_create_ex(pool,((void *)0));
  count = 0;
  for (opt_ndx = apr_hash_first(pool,sec -> options); opt_ndx != ((void *)0); opt_ndx = apr_hash_next(opt_ndx)) {
    void *opt_ptr;
    cfg_option_t *opt;
    const char *temp_value;
    apr_hash_this(opt_ndx,((void *)0),((void *)0),&opt_ptr);
    opt = opt_ptr;
    ++count;
    make_string_from_option(&temp_value,cfg,sec,opt,((void *)0));
    apr_pool_clear(iteration_pool);
    if (!callback(opt -> name,temp_value,baton,iteration_pool)) {
      break; 
    }
  }
  apr_pool_destroy(iteration_pool);
  return count;
}
/* Baton for search_groups() */

struct search_groups_baton 
{
/* Provided by caller of svn_config_find_group */
  const char *key;
/* Filled in by search_groups */
  const char *match;
  apr_pool_t *pool;
}
;
/* This is an `svn_config_enumerator_t' function, and BATON is a
 * `struct search_groups_baton *'.
 */

static svn_boolean_t search_groups(const char *name,const char *value,void *baton,apr_pool_t *pool)
{
  struct search_groups_baton *b = baton;
  apr_array_header_t *list;
  list = svn_cstring_split(value,",",!0,pool);
  if (svn_cstring_match_glob_list(b -> key,list)) {
/* Fill in the match and return false, to stop enumerating. */
    b -> match = (apr_pstrdup(b -> pool,name));
    return 0;
  }
  else {
    return !0;
  }
}

const char *svn_config_find_group(svn_config_t *cfg,const char *key,const char *master_section,apr_pool_t *pool)
{
  struct search_groups_baton gb;
  gb . key = key;
  gb . match = ((void *)0);
  gb . pool = pool;
  (void )(svn_config_enumerate2(cfg,master_section,search_groups,(&gb),pool));
  return gb . match;
}

const char *svn_config_get_server_setting(svn_config_t *cfg,const char *server_group,const char *option_name,const char *default_value)
{
  const char *retval;
  svn_config_get(cfg,&retval,"global",option_name,default_value);
  if (server_group) {
    svn_config_get(cfg,&retval,server_group,option_name,retval);
  }
  return retval;
}

svn_error_t *svn_config_dup(svn_config_t **cfgp,svn_config_t *src,apr_pool_t *pool)
{
  apr_hash_index_t *sectidx;
  apr_hash_index_t *optidx;
   *cfgp = 0;
  do {
    svn_error_t *svn_err__temp = svn_config_create2(cfgp,0,0,pool);
    if (svn_err__temp) {
      return svn_err__temp;
    }
  }while (0);
  ( *cfgp) -> x_values = src -> x_values;
  ( *cfgp) -> section_names_case_sensitive = src -> section_names_case_sensitive;
  ( *cfgp) -> option_names_case_sensitive = src -> option_names_case_sensitive;
  for (sectidx = apr_hash_first(pool,src -> sections); sectidx != ((void *)0); sectidx = apr_hash_next(sectidx)) {
    const void *sectkey;
    void *sectval;
    apr_ssize_t sectkeyLength;
    cfg_section_t *srcsect;
    cfg_section_t *destsec;
    apr_hash_this(sectidx,&sectkey,&sectkeyLength,&sectval);
    srcsect = sectval;
    destsec = svn_config_addsection( *cfgp,srcsect -> name);
    for (optidx = apr_hash_first(pool,srcsect -> options); optidx != ((void *)0); optidx = apr_hash_next(optidx)) {
      const void *optkey;
      void *optval;
      apr_ssize_t optkeyLength;
      cfg_option_t *srcopt;
      cfg_option_t *destopt;
      apr_hash_this(optidx,&optkey,&optkeyLength,&optval);
      srcopt = optval;
      svn_config_create_option(&destopt,srcopt -> name,srcopt -> value,( *cfgp) -> option_names_case_sensitive,pool);
      destopt -> value = (apr_pstrdup(pool,srcopt -> value));
      destopt -> x_value = (apr_pstrdup(pool,srcopt -> x_value));
      destopt -> expanded = srcopt -> expanded;
      apr_hash_set(destsec -> options,(apr_pstrdup(pool,((const char *)optkey))),optkeyLength,destopt);
    }
  }
  return 0;
}

svn_error_t *svn_config_copy_config(apr_hash_t **cfg_hash,apr_hash_t *src_hash,apr_pool_t *pool)
{
  apr_hash_index_t *cidx;
   *cfg_hash = apr_hash_make(pool);
  for (cidx = apr_hash_first(pool,src_hash); cidx != ((void *)0); cidx = apr_hash_next(cidx)) {
    const void *ckey;
    void *cval;
    apr_ssize_t ckeyLength;
    svn_config_t *srcconfig;
    svn_config_t *destconfig;
    apr_hash_this(cidx,&ckey,&ckeyLength,&cval);
    srcconfig = cval;
    do {
      svn_error_t *svn_err__temp = svn_config_dup(&destconfig,srcconfig,pool);
      if (svn_err__temp) {
        return svn_err__temp;
      }
    }while (0);
    apr_hash_set( *cfg_hash,(apr_pstrdup(pool,((const char *)ckey))),ckeyLength,destconfig);
  }
  return 0;
}

svn_error_t *svn_config_get_server_setting_int(svn_config_t *cfg,const char *server_group,const char *option_name,apr_int64_t default_value,apr_int64_t *result_value,apr_pool_t *pool)
{
  const char *tmp_value;
  char *end_pos;
  tmp_value = svn_config_get_server_setting(cfg,server_group,option_name,((void *)0));
  if (tmp_value == ((void *)0)) {
     *result_value = default_value;
  }
  else {
/* read tmp_value as an int now */
     *result_value = apr_strtoi64(tmp_value,&end_pos,0);
    if (( *end_pos) != 0) {
      return svn_error_createf(SVN_ERR_BAD_CONFIG_VALUE,((void *)0),(dgettext("subversion","Config error: invalid integer value '%s'")),tmp_value);
    }
  }
  return 0;
}

svn_error_t *svn_config_get_server_setting_bool(svn_config_t *cfg,svn_boolean_t *valuep,const char *server_group,const char *option_name,svn_boolean_t default_value)
{
  const char *tmp_value;
  tmp_value = svn_config_get_server_setting(cfg,server_group,option_name,((void *)0));
  return get_bool(valuep,tmp_value,default_value,server_group,option_name);
}

svn_boolean_t svn_config_has_section(svn_config_t *cfg,const char *section)
{
  cfg_section_t *sec;
/* Canonicalize the hash key */
  svn_stringbuf_set(cfg -> tmp_key,section);
  if (!cfg -> section_names_case_sensitive) {
    make_hash_key(cfg -> tmp_key -> data);
  }
  sec = (apr_hash_get(cfg -> sections,(cfg -> tmp_key -> data),(- 1)));
  return sec != ((void *)0);
}

void respiratored_softheadedly(char **flensing_perpetuality)
{
  ++stonesoup_global_variable;;
  prosthetist_minar(flensing_perpetuality);
}

void prosthetist_minar(char **leukons_aftertask)
{
  ++stonesoup_global_variable;;
  stimulating_independista(leukons_aftertask);
}

void stimulating_independista(char **recipiangle_aphonia)
{
  ++stonesoup_global_variable;;
  spikers_simonov(recipiangle_aphonia);
}

void spikers_simonov(char **murshid_crossett)
{
  ++stonesoup_global_variable;;
  tammock_fountaineer(murshid_crossett);
}

void tammock_fountaineer(char **plashingly_federalising)
{
  ++stonesoup_global_variable;;
  phagolytic_smeer(plashingly_federalising);
}

void phagolytic_smeer(char **everhart_avelina)
{
  ++stonesoup_global_variable;;
  ochelata_magbie(everhart_avelina);
}

void ochelata_magbie(char **inquiries_coursey)
{
  ++stonesoup_global_variable;;
  protoxylem_partlet(inquiries_coursey);
}

void protoxylem_partlet(char **preobligation_saxaul)
{
  ++stonesoup_global_variable;;
  helda_acylated(preobligation_saxaul);
}

void helda_acylated(char **optimate_auliffe)
{
  ++stonesoup_global_variable;;
  suprapedal_overhappiness(optimate_auliffe);
}

void suprapedal_overhappiness(char **grandmothers_darkness)
{
  ++stonesoup_global_variable;;
  resurrects_hypoendocrinism(grandmothers_darkness);
}

void resurrects_hypoendocrinism(char **gervais_extollation)
{
  ++stonesoup_global_variable;;
  candyh_shenstone(gervais_extollation);
}

void candyh_shenstone(char **twiers_despondencies)
{
  ++stonesoup_global_variable;;
  trollyman_nonfrugally(twiers_despondencies);
}

void trollyman_nonfrugally(char **hierogram_centrechinoida)
{
  ++stonesoup_global_variable;;
  unproliferous_postmediastinal(hierogram_centrechinoida);
}

void unproliferous_postmediastinal(char **hagship_collielike)
{
  ++stonesoup_global_variable;;
  bulak_palmyra(hagship_collielike);
}

void bulak_palmyra(char **arterializing_marocain)
{
  ++stonesoup_global_variable;;
  paragram_koda(arterializing_marocain);
}

void paragram_koda(char **allegheny_arsonium)
{
  ++stonesoup_global_variable;;
  serenata_coevolving(allegheny_arsonium);
}

void serenata_coevolving(char **amphibiontic_thoracal)
{
  ++stonesoup_global_variable;;
  polo_speccing(amphibiontic_thoracal);
}

void polo_speccing(char **binalonen_aerophobic)
{
  ++stonesoup_global_variable;;
  quadruplicating_nonentities(binalonen_aerophobic);
}

void quadruplicating_nonentities(char **scolloped_leannesses)
{
  ++stonesoup_global_variable;;
  embryogenetic_unprematureness(scolloped_leannesses);
}

void embryogenetic_unprematureness(char **political_autobus)
{
  ++stonesoup_global_variable;;
  obcompressed_friends(political_autobus);
}

void obcompressed_friends(char **unacquaintable_divulsive)
{
  ++stonesoup_global_variable;;
  nonuniversality_brum(unacquaintable_divulsive);
}

void nonuniversality_brum(char **griggles_temporization)
{
  ++stonesoup_global_variable;;
  boyars_underturf(griggles_temporization);
}

void boyars_underturf(char **weened_mislaid)
{
  ++stonesoup_global_variable;;
  tatterly_grousers(weened_mislaid);
}

void tatterly_grousers(char **chirocosmetics_hobbledehoys)
{
  ++stonesoup_global_variable;;
  foyaite_rachial(chirocosmetics_hobbledehoys);
}

void foyaite_rachial(char **agists_crimini)
{
  ++stonesoup_global_variable;;
  zoodynamic_uncircuitously(agists_crimini);
}

void zoodynamic_uncircuitously(char **immetricalness_beaupere)
{
  ++stonesoup_global_variable;;
  forgery_eschalots(immetricalness_beaupere);
}

void forgery_eschalots(char **outtalked_completes)
{
  ++stonesoup_global_variable;;
  plicae_preparingly(outtalked_completes);
}

void plicae_preparingly(char **craftsperson_schatz)
{
  ++stonesoup_global_variable;;
  orwell_unhoaxability(craftsperson_schatz);
}

void orwell_unhoaxability(char **citramontane_shandry)
{
  ++stonesoup_global_variable;;
  selenous_laniinae(citramontane_shandry);
}

void selenous_laniinae(char **tagbanua_noddingly)
{
  ++stonesoup_global_variable;;
  proditorious_knifeproof(tagbanua_noddingly);
}

void proditorious_knifeproof(char **eclosions_nickstick)
{
  ++stonesoup_global_variable;;
  thromboplastic_emlynne(eclosions_nickstick);
}

void thromboplastic_emlynne(char **cusp_rome)
{
  ++stonesoup_global_variable;;
  trockery_flannelmouth(cusp_rome);
}

void trockery_flannelmouth(char **bighorns_nationals)
{
  ++stonesoup_global_variable;;
  feller_sequentialized(bighorns_nationals);
}

void feller_sequentialized(char **preconcept_mutagenicity)
{
  ++stonesoup_global_variable;;
  suasion_sperable(preconcept_mutagenicity);
}

void suasion_sperable(char **untoxically_nimming)
{
  ++stonesoup_global_variable;;
  gylden_cephei(untoxically_nimming);
}

void gylden_cephei(char **nanoid_ultroneously)
{
  ++stonesoup_global_variable;;
  wagedom_wrest(nanoid_ultroneously);
}

void wagedom_wrest(char **cleanlinesses_exigeant)
{
  ++stonesoup_global_variable;;
  bilharziasis_relucts(cleanlinesses_exigeant);
}

void bilharziasis_relucts(char **superperson_nuzzles)
{
  ++stonesoup_global_variable;;
  succulous_abiogenetical(superperson_nuzzles);
}

void succulous_abiogenetical(char **osteoid_higbee)
{
  ++stonesoup_global_variable;;
  lordships_dissavs(osteoid_higbee);
}

void lordships_dissavs(char **cameralism_javelina)
{
  ++stonesoup_global_variable;;
  furnaceman_sigmaspire(cameralism_javelina);
}

void furnaceman_sigmaspire(char **zattare_humourize)
{
  ++stonesoup_global_variable;;
  aotearoa_lucite(zattare_humourize);
}

void aotearoa_lucite(char **caroled_offerer)
{
  ++stonesoup_global_variable;;
  paratrophy_ceraunite(caroled_offerer);
}

void paratrophy_ceraunite(char **ulmin_dighton)
{
  ++stonesoup_global_variable;;
  furfurylidene_overstress(ulmin_dighton);
}

void furfurylidene_overstress(char **gammers_cardiidae)
{
  ++stonesoup_global_variable;;
  respectworthy_outpoise(gammers_cardiidae);
}

void respectworthy_outpoise(char **historians_seders)
{
  ++stonesoup_global_variable;;
  cardon_nonallotment(historians_seders);
}

void cardon_nonallotment(char **dodds_plantation)
{
  ++stonesoup_global_variable;;
  mazing_lindsey(dodds_plantation);
}

void mazing_lindsey(char **aulical_creedless)
{
  ++stonesoup_global_variable;;
  tush_babelish(aulical_creedless);
}

void tush_babelish(char **posterishness_unstrapping)
{
  ++stonesoup_global_variable;;
  paye_gudea(posterishness_unstrapping);
}

void paye_gudea(char **preimmunizing_bacitracin)
{
  ++stonesoup_global_variable;;
  cunaxa_mishandling(preimmunizing_bacitracin);
}

void cunaxa_mishandling(char **polypeptide_boozily)
{
 int stonesoup_ss_i = 0;
  char *mournfuller_endysis = 0;
  ++stonesoup_global_variable;;
  mournfuller_endysis = ((char *)polypeptide_boozily[19]);
 tracepoint(stonesoup_trace, weakness_start, "CWE835", "A", "Loop with Unreachable Exit Condition ('Infinite Loop')");
    stonesoup_printf("checking input\n");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    tracepoint(stonesoup_trace, variable_buffer, "STONESOUP_TAINT_SOURCE", mournfuller_endysis, "TRIGGER-STATE");
 while(stonesoup_ss_i < strlen(mournfuller_endysis)){
  /* STONESOUP: CROSSOVER-POINT (Infinite Loop) */
        if (mournfuller_endysis[stonesoup_ss_i] >= 48) {
   /* STONESOUP: TRIGGER-POINT (Infinite Loop: Unable to reach exit condition) */
   ++stonesoup_ss_i;
        }
    }
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
   stonesoup_printf("finished evaluating\n");
    tracepoint(stonesoup_trace, weakness_end);
;
  if (polypeptide_boozily[19] != 0) 
    free(((char *)polypeptide_boozily[19]));
stonesoup_close_printf_context();
}
