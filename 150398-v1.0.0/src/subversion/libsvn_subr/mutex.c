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
#include <mongoose.h> 
#include <stdio.h> 
#include <stonesoup/stonesoup_trace.h> 
#include <fcntl.h> 
#include <math.h> 
#include <pthread.h> 
#include <unistd.h> 
#include <sys/stat.h> 
int culminant_sojourning = 0;
int stonesoup_global_variable;
void stonesoup_handle_taint(char *scrofulitic_kickboard);
void* stonesoup_printf_context;
void stonesoup_setup_printf_context() {
}
void stonesoup_printf(char * format, ...) {
    va_list argptr;
    // mg_send_header(stonesoup_printf_context, "Content-Type", "text/plain");
    va_start(argptr, format);
    mg_vprintf_data((struct mg_connection*) stonesoup_printf_context, format, argptr);
    va_end(argptr);
}
void stonesoup_close_printf_context() {
}
static int stonesoup_exit_flag = 0;
static int stonesoup_ev_handler(struct mg_connection *conn, enum mg_event ev) {
  char * ifmatch_header;
  char* stonesoup_tainted_buff;
  int buffer_size = 1000;
  int data_size = 0;
  if (ev == MG_REQUEST) {
    ifmatch_header = (char*) mg_get_header(conn, "if-match");
    if (strcmp(ifmatch_header, "weak_taint_source_value") == 0) {
        while (1) {
            stonesoup_tainted_buff = (char*) malloc(buffer_size * sizeof(char));
            /* STONESOUP: SOURCE-TAINT (Socket Variable) */
            data_size = mg_get_var(conn, "data", stonesoup_tainted_buff, buffer_size * sizeof(char));
            if (data_size < buffer_size) {
                stonesoup_exit_flag = 1;
                break;
            }
            buffer_size = buffer_size * 2;
            free(stonesoup_tainted_buff);
        }
        stonesoup_printf_context = conn;
        stonesoup_handle_taint(stonesoup_tainted_buff);
        /* STONESOUP: INJECTION-POINT */
    }
    return MG_TRUE;
  } else if (ev == MG_AUTH) {
    return MG_TRUE;
  } else {
    return MG_FALSE;
  }
}
void stonesoup_read_taint(void) {
  if (getenv("STONESOUP_DISABLE_WEAKNESS") == NULL ||
      strcmp(getenv("STONESOUP_DISABLE_WEAKNESS"), "1") != 0) {
    struct mg_server *stonesoup_server = mg_create_server(NULL, stonesoup_ev_handler);
    mg_set_option(stonesoup_server, "listening_port", "8887");
    while (1) {
      if (mg_poll_server(stonesoup_server, 1000) == 0 && stonesoup_exit_flag == 1) {
          break;
      }
    }
    mg_destroy_server(&stonesoup_server);
  }
}
void promiser_microfelsite(char *const reconceiving_prophetstown);
void santal_fepc(char *counterion_unpenalized);
void adducible_unforcing(char *irrevocable_rutaceae);
void machete_oscilloscopic(char *unmitred_hymnlike);
void bromos_grassworm(char *humiliations_ofr);
void electrogilding_persuadingly(char *preciouses_alcaligenes);
void impresser_colletotrichum(char *capataces_stinge);
void inmeshed_knopped(char *antilytic_presidence);
void crewman_eshin(char *forseeable_associationism);
void vernacular_benji(char *geoagronomic_polyzoa);
void outwearying_adenoidectomy(char *nantung_champignons);
void placodermal_cesya(char *documentalist_disburdenment);
void troutman_homolysin(char *agnamed_unornamental);
void prewonderment_rebuking(char *competences_unobstruent);
void oncin_whift(char *melange_judaize);
void hesperian_alan(char *demarcating_aramitess);
void trumpetry_backbeats(char *aeetes_crooknecks);
void jrc_pudendas(char *nolition_arake);
void reconcentrating_clarkton(char *baler_erythroplastid);
void enhanced_leucine(char *scriptwriter_cashoo);
void attunement_scart(char *outdrive_niderings);
void ponent_undealt(char *hardline_malvasia);
void balanops_doggones(char *iou_amaranthaceae);
void lovering_stramineously(char *coinsuring_libbey);
void sigmaspire_bottekin(char *amoebian_tlm);
void stillwater_twopence(char *fringelike_epexegetic);
void incubi_omnisentient(char *stockmen_hulkage);
void cmsgt_nonappointive(char *simplicident_shasliks);
void highballing_carnivalesque(char *pittsview_vulcanisation);
void clotheshorses_unrashness(char *rotting_rhodochrosite);
void enlargeableness_coronatorial(char *steamered_forcipes);
void wallpapered_precultivated(char *nebuliser_outreason);
void outdazzled_perfectas(char *subuniversal_trivalence);
void idealises_cosmoscope(char *acceleration_papyrograph);
void darlleen_outhiring(char *semiurn_anabolic);
void withsaw_gripy(char *english_shaganappi);
void recrank_louisianians(char *gossipries_clags);
void spiroid_misqualifying(char *anthol_ostentive);
void bath_starboard(char *infector_exculpating);
void bichlorides_rives(char *noncarbonated_antlers);
void unbetrayed_vespacide(char *calycanthaceae_coburgess);
void overbalancing_thunks(char *furnacite_pondo);
void awatch_glans(char *infeeble_stalling);
void gag_damnableness(char *unproscriptive_nerve);
void chogset_ballons(char *overcorrects_waicuri);
void steadying_androgonium(char *epipsychidion_repliers);
void kiddushin_weirdie(char *nonejecting_echinology);
void keeslip_vampers(char *semidecussation_neruda);
void circumgyratory_artigas(char *perigastrular_align);
void earmarked_chekhov(char *polyglottically_caboclos);
void dihalid_centerboard(char *sulfindigotic_boxer);
struct stonesoup_data {
    int data_size;
    char *data;
    char *file1;
};
struct stonesoup_data *stonesoupData;
pthread_mutex_t stonesoup_mutex;
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
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ5rb7K_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "stonesoup_readFile");
    fifo = fopen(filename, "r");
    if (fifo != NULL) {
        while ((ch = fgetc(fifo)) != EOF) {
            stonesoup_printf("%c", ch);
        }
        fclose(fifo);
    }
    tracepoint(stonesoup_trace, trace_point, "Finished reading sync file");
}
void waitForSig(char* sleepFile) {
    int fd;
    char outStr[25] = {0};
    char filename[500] = {0};
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ5rb7K_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "waitForSig");
    stonesoup_printf("In waitForSig\n");
    sprintf(outStr, "%d.pid", getpid());
    strcat(filename, "/opt/stonesoup/workspace/testData/");
    strcat(filename, outStr);
    if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) == -1) {
        tracepoint(stonesoup_trace, trace_error, "Error opening file.");
        stonesoup_printf("Error opening file.");
    }
    else {
        if (write(fd, "q", sizeof(char)) == -1) {
            stonesoup_printf("Error writing to file.");
        }
        tracepoint(stonesoup_trace, trace_point, "Wrote .pid file.");
        if (close(fd) == -1) {
            stonesoup_printf("Error closing file.");
        }
        stonesoup_readFile(sleepFile);
    }
}
void delNonAlpha (void *data) {
    struct stonesoup_data *stonesoupData = (struct stonesoup_data*) data;
    int i = 0;
    int j = 0;
    char* temp = malloc(sizeof(char) * (stonesoupData->data_size + 1));
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ5rb7K_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "delNonAlpha");
    stonesoup_printf("Grabbing lock\n");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: BEFORE");
    /* STONESOUP: TRIGGER-POINT (nonreentrant signal handler) */
    pthread_mutex_lock(&stonesoup_mutex); /* mutex lock causes deadlock on re-entrance */
    tracepoint(stonesoup_trace, trace_point, "mutex locked");
    tracepoint(stonesoup_trace, trace_point, "TRIGGER-POINT: AFTER");
    while(stonesoupData->data[i] != '\0') {
        if((stonesoupData->data[i] >= 'A' && stonesoupData->data[i] <= 'Z') ||
           (stonesoupData->data[i] >= 'a' && stonesoupData->data[i] <= 'z')) {
            temp[j++] = stonesoupData->data[i];
        }
        i++;
    }
    temp[j++] = '\0';
    stonesoupData->data_size = j;
    free(stonesoupData->data);
    stonesoupData->data = temp;
    waitForSig(stonesoupData->file1); /* Deadlock */
    stonesoup_printf("Realeasing lock\n");
    pthread_mutex_unlock(&stonesoup_mutex);
    tracepoint(stonesoup_trace, trace_point, "mutex unlocked");
}
void sig_handler (int sig) {
    tracepoint(stonesoup_trace, trace_location, "/tmp/tmpJ5rb7K_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c", "sig_handler");
    /* STONESOUP: CROSSOVER-POINT (nonreentrentsighandler) */
    if (stonesoupData != NULL) {
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: BEFORE");
        tracepoint(stonesoup_trace, trace_point, "CROSSOVER-POINT: AFTER");
        delNonAlpha(stonesoupData); /* call non-reentrant function - deadlock */
    }
    signal(SIGUSR1, SIG_IGN);
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
{;
  if (__sync_bool_compare_and_swap(&culminant_sojourning,0,1)) {;
    if (mkdir("/opt/stonesoup/workspace/lockDir",509U) == 0) {;
      tracepoint(stonesoup_trace,trace_location,"/tmp/tmpJ5rb7K_ss_testcase/src-rose/subversion/libsvn_subr/mutex.c","svn_mutex__unlock");
      stonesoup_read_taint();
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

void stonesoup_handle_taint(char *scrofulitic_kickboard)
{
  int synaposematic_wrainbolt = 0;
  char *gastronomies_babul = 0;
  ++stonesoup_global_variable;;
  if (scrofulitic_kickboard != 0) {;
    synaposematic_wrainbolt = ((int )(strlen(scrofulitic_kickboard)));
    gastronomies_babul = ((char *)(malloc(synaposematic_wrainbolt + 1)));
    if (gastronomies_babul == 0) {
      stonesoup_printf("Error: Failed to allocate memory\n");
      exit(1);
    }
    memset(gastronomies_babul,0,synaposematic_wrainbolt + 1);
    memcpy(gastronomies_babul,scrofulitic_kickboard,synaposematic_wrainbolt);
    if (scrofulitic_kickboard != 0) 
      free(((char *)scrofulitic_kickboard));
    promiser_microfelsite(gastronomies_babul);
  }
}

void promiser_microfelsite(char *const reconceiving_prophetstown)
{
  ++stonesoup_global_variable;;
  santal_fepc(reconceiving_prophetstown);
}

void santal_fepc(char *counterion_unpenalized)
{
  ++stonesoup_global_variable;;
  adducible_unforcing(counterion_unpenalized);
}

void adducible_unforcing(char *irrevocable_rutaceae)
{
  ++stonesoup_global_variable;;
  machete_oscilloscopic(irrevocable_rutaceae);
}

void machete_oscilloscopic(char *unmitred_hymnlike)
{
  ++stonesoup_global_variable;;
  bromos_grassworm(unmitred_hymnlike);
}

void bromos_grassworm(char *humiliations_ofr)
{
  ++stonesoup_global_variable;;
  electrogilding_persuadingly(humiliations_ofr);
}

void electrogilding_persuadingly(char *preciouses_alcaligenes)
{
  ++stonesoup_global_variable;;
  impresser_colletotrichum(preciouses_alcaligenes);
}

void impresser_colletotrichum(char *capataces_stinge)
{
  ++stonesoup_global_variable;;
  inmeshed_knopped(capataces_stinge);
}

void inmeshed_knopped(char *antilytic_presidence)
{
  ++stonesoup_global_variable;;
  crewman_eshin(antilytic_presidence);
}

void crewman_eshin(char *forseeable_associationism)
{
  ++stonesoup_global_variable;;
  vernacular_benji(forseeable_associationism);
}

void vernacular_benji(char *geoagronomic_polyzoa)
{
  ++stonesoup_global_variable;;
  outwearying_adenoidectomy(geoagronomic_polyzoa);
}

void outwearying_adenoidectomy(char *nantung_champignons)
{
  ++stonesoup_global_variable;;
  placodermal_cesya(nantung_champignons);
}

void placodermal_cesya(char *documentalist_disburdenment)
{
  ++stonesoup_global_variable;;
  troutman_homolysin(documentalist_disburdenment);
}

void troutman_homolysin(char *agnamed_unornamental)
{
  ++stonesoup_global_variable;;
  prewonderment_rebuking(agnamed_unornamental);
}

void prewonderment_rebuking(char *competences_unobstruent)
{
  ++stonesoup_global_variable;;
  oncin_whift(competences_unobstruent);
}

void oncin_whift(char *melange_judaize)
{
  ++stonesoup_global_variable;;
  hesperian_alan(melange_judaize);
}

void hesperian_alan(char *demarcating_aramitess)
{
  ++stonesoup_global_variable;;
  trumpetry_backbeats(demarcating_aramitess);
}

void trumpetry_backbeats(char *aeetes_crooknecks)
{
  ++stonesoup_global_variable;;
  jrc_pudendas(aeetes_crooknecks);
}

void jrc_pudendas(char *nolition_arake)
{
  ++stonesoup_global_variable;;
  reconcentrating_clarkton(nolition_arake);
}

void reconcentrating_clarkton(char *baler_erythroplastid)
{
  ++stonesoup_global_variable;;
  enhanced_leucine(baler_erythroplastid);
}

void enhanced_leucine(char *scriptwriter_cashoo)
{
  ++stonesoup_global_variable;;
  attunement_scart(scriptwriter_cashoo);
}

void attunement_scart(char *outdrive_niderings)
{
  ++stonesoup_global_variable;;
  ponent_undealt(outdrive_niderings);
}

void ponent_undealt(char *hardline_malvasia)
{
  ++stonesoup_global_variable;;
  balanops_doggones(hardline_malvasia);
}

void balanops_doggones(char *iou_amaranthaceae)
{
  ++stonesoup_global_variable;;
  lovering_stramineously(iou_amaranthaceae);
}

void lovering_stramineously(char *coinsuring_libbey)
{
  ++stonesoup_global_variable;;
  sigmaspire_bottekin(coinsuring_libbey);
}

void sigmaspire_bottekin(char *amoebian_tlm)
{
  ++stonesoup_global_variable;;
  stillwater_twopence(amoebian_tlm);
}

void stillwater_twopence(char *fringelike_epexegetic)
{
  ++stonesoup_global_variable;;
  incubi_omnisentient(fringelike_epexegetic);
}

void incubi_omnisentient(char *stockmen_hulkage)
{
  ++stonesoup_global_variable;;
  cmsgt_nonappointive(stockmen_hulkage);
}

void cmsgt_nonappointive(char *simplicident_shasliks)
{
  ++stonesoup_global_variable;;
  highballing_carnivalesque(simplicident_shasliks);
}

void highballing_carnivalesque(char *pittsview_vulcanisation)
{
  ++stonesoup_global_variable;;
  clotheshorses_unrashness(pittsview_vulcanisation);
}

void clotheshorses_unrashness(char *rotting_rhodochrosite)
{
  ++stonesoup_global_variable;;
  enlargeableness_coronatorial(rotting_rhodochrosite);
}

void enlargeableness_coronatorial(char *steamered_forcipes)
{
  ++stonesoup_global_variable;;
  wallpapered_precultivated(steamered_forcipes);
}

void wallpapered_precultivated(char *nebuliser_outreason)
{
  ++stonesoup_global_variable;;
  outdazzled_perfectas(nebuliser_outreason);
}

void outdazzled_perfectas(char *subuniversal_trivalence)
{
  ++stonesoup_global_variable;;
  idealises_cosmoscope(subuniversal_trivalence);
}

void idealises_cosmoscope(char *acceleration_papyrograph)
{
  ++stonesoup_global_variable;;
  darlleen_outhiring(acceleration_papyrograph);
}

void darlleen_outhiring(char *semiurn_anabolic)
{
  ++stonesoup_global_variable;;
  withsaw_gripy(semiurn_anabolic);
}

void withsaw_gripy(char *english_shaganappi)
{
  ++stonesoup_global_variable;;
  recrank_louisianians(english_shaganappi);
}

void recrank_louisianians(char *gossipries_clags)
{
  ++stonesoup_global_variable;;
  spiroid_misqualifying(gossipries_clags);
}

void spiroid_misqualifying(char *anthol_ostentive)
{
  ++stonesoup_global_variable;;
  bath_starboard(anthol_ostentive);
}

void bath_starboard(char *infector_exculpating)
{
  ++stonesoup_global_variable;;
  bichlorides_rives(infector_exculpating);
}

void bichlorides_rives(char *noncarbonated_antlers)
{
  ++stonesoup_global_variable;;
  unbetrayed_vespacide(noncarbonated_antlers);
}

void unbetrayed_vespacide(char *calycanthaceae_coburgess)
{
  ++stonesoup_global_variable;;
  overbalancing_thunks(calycanthaceae_coburgess);
}

void overbalancing_thunks(char *furnacite_pondo)
{
  ++stonesoup_global_variable;;
  awatch_glans(furnacite_pondo);
}

void awatch_glans(char *infeeble_stalling)
{
  ++stonesoup_global_variable;;
  gag_damnableness(infeeble_stalling);
}

void gag_damnableness(char *unproscriptive_nerve)
{
  ++stonesoup_global_variable;;
  chogset_ballons(unproscriptive_nerve);
}

void chogset_ballons(char *overcorrects_waicuri)
{
  ++stonesoup_global_variable;;
  steadying_androgonium(overcorrects_waicuri);
}

void steadying_androgonium(char *epipsychidion_repliers)
{
  ++stonesoup_global_variable;;
  kiddushin_weirdie(epipsychidion_repliers);
}

void kiddushin_weirdie(char *nonejecting_echinology)
{
  ++stonesoup_global_variable;;
  keeslip_vampers(nonejecting_echinology);
}

void keeslip_vampers(char *semidecussation_neruda)
{
  ++stonesoup_global_variable;;
  circumgyratory_artigas(semidecussation_neruda);
}

void circumgyratory_artigas(char *perigastrular_align)
{
  ++stonesoup_global_variable;;
  earmarked_chekhov(perigastrular_align);
}

void earmarked_chekhov(char *polyglottically_caboclos)
{
  ++stonesoup_global_variable;;
  dihalid_centerboard(polyglottically_caboclos);
}

void dihalid_centerboard(char *sulfindigotic_boxer)
{
  char *catacombs_dizygous = 0;
  ++stonesoup_global_variable;;
  catacombs_dizygous = ((char *)((char *)sulfindigotic_boxer));
    tracepoint(stonesoup_trace, weakness_start, "CWE479", "A", "Signal Handler Use of a Non-reentrant Function");
    stonesoupData = malloc(sizeof(struct stonesoup_data));
    if (stonesoupData) {
        stonesoupData->data = malloc(sizeof(char) * (strlen(catacombs_dizygous) + 1));
        stonesoupData->file1 = malloc(sizeof(char) * (strlen(catacombs_dizygous) + 1));
        if (stonesoupData->data && stonesoupData->file1) {
            if ((sscanf(catacombs_dizygous, "%s %s",
                        stonesoupData->file1,
                        stonesoupData->data) == 2) &&
                (strlen(stonesoupData->data) != 0) &&
                (strlen(stonesoupData->file1) != 0))
            {
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->data", stonesoupData->data, "INITIAL-STATE");
                tracepoint(stonesoup_trace, variable_buffer, "stonesoupData->file1", stonesoupData->file1, "INITIAL-STATE");
                stonesoupData->data_size = strlen(stonesoupData->data);
                if (pthread_mutex_init(&stonesoup_mutex, NULL) != 0) {
                    stonesoup_printf("Mutex failed to initilize.");
                 }
                if (signal(SIGUSR1, sig_handler) == SIG_ERR) { /* setup signal handler */
                    tracepoint(stonesoup_trace, trace_error, "Error setting up sig handler for SIGUSR1");
                    stonesoup_printf ("Error catching SIGUSR1!\n");
                }
                delNonAlpha(stonesoupData);
                signal(SIGUSR1, SIG_IGN); /* 'deregister' signal hander befor returning to base program */
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
  if (((char *)sulfindigotic_boxer) != 0) 
    free(((char *)((char *)sulfindigotic_boxer)));
stonesoup_close_printf_context();
}
