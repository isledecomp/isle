#ifndef SCRIPTS_H
#define SCRIPTS_H

class MxAtomId;

extern MxAtomId* g_copterScript;
extern MxAtomId* g_dunecarScript;
extern MxAtomId* g_jetskiScript;
extern MxAtomId* g_racecarScript;
extern MxAtomId* g_carraceScript;
extern MxAtomId* g_carracerScript;
extern MxAtomId* g_jetraceScript;
extern MxAtomId* g_jetracerScript;
extern MxAtomId* g_isleScript;
extern MxAtomId* g_elevbottScript;
extern MxAtomId* g_infodoorScript;
extern MxAtomId* g_infomainScript;
extern MxAtomId* g_infoscorScript;
extern MxAtomId* g_regbookScript;
extern MxAtomId* g_histbookScript;
extern MxAtomId* g_hospitalScript;
extern MxAtomId* g_policeScript;
extern MxAtomId* g_garageScript;
extern MxAtomId* g_act2mainScript;
extern MxAtomId* g_act3Script;
extern MxAtomId* g_jukeboxScript;
extern MxAtomId* g_pz5Script;
extern MxAtomId* g_introScript;
extern MxAtomId* g_testScript;
extern MxAtomId* g_jukeboxwScript;
extern MxAtomId* g_sndAnimScript;
extern MxAtomId* g_creditsScript;
extern MxAtomId* g_nocdSourceName;

void CreateScripts();
void DestroyScripts();
const char* GetNoCD_SourceName();

#endif // SCRIPTS_H
