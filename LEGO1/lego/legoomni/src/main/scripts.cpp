#include "scripts.h"

#include "mxatom.h"

// GLOBAL: LEGO1 0x100f451c
MxAtomId* g_copterScript = NULL;

// GLOBAL: LEGO1 0x100f4520
MxAtomId* g_dunecarScript = NULL;

// GLOBAL: LEGO1 0x100f4524
MxAtomId* g_jetskiScript = NULL;

// GLOBAL: LEGO1 0x100f4528
MxAtomId* g_racecarScript = NULL;

// GLOBAL: LEGO1 0x100f452c
// GLOBAL: BETA10 0x10211514
MxAtomId* g_carraceScript = NULL;

// GLOBAL: LEGO1 0x100f4530
MxAtomId* g_carracerScript = NULL;

// GLOBAL: LEGO1 0x100f4534
MxAtomId* g_jetraceScript = NULL;

// GLOBAL: LEGO1 0x100f4538
MxAtomId* g_jetracerScript = NULL;

// GLOBAL: LEGO1 0x100f453c
// GLOBAL: BETA10 0x10211534
MxAtomId* g_isleScript = NULL;

// GLOBAL: LEGO1 0x100f4540
MxAtomId* g_elevbottScript = NULL;

// GLOBAL: LEGO1 0x100f4544
MxAtomId* g_infodoorScript = NULL;

// GLOBAL: LEGO1 0x100f4548
// GLOBAL: BETA10 0x102114dc
MxAtomId* g_infomainScript = NULL;

// GLOBAL: LEGO1 0x100f454c
MxAtomId* g_infoscorScript = NULL;

// GLOBAL: LEGO1 0x100f4550
MxAtomId* g_regbookScript = NULL;

// GLOBAL: LEGO1 0x100f4554
MxAtomId* g_histbookScript = NULL;

// GLOBAL: LEGO1 0x100f4558
MxAtomId* g_hospitalScript = NULL;

// GLOBAL: LEGO1 0x100f455c
MxAtomId* g_policeScript = NULL;

// GLOBAL: LEGO1 0x100f4560
MxAtomId* g_garageScript = NULL;

// GLOBAL: LEGO1 0x100f4564
MxAtomId* g_act2mainScript = NULL;

// GLOBAL: LEGO1 0x100f4568
MxAtomId* g_act3Script = NULL;

// GLOBAL: LEGO1 0x100f456c
// GLOBAL: BETA10 0x102114e0
MxAtomId* g_jukeboxScript = NULL;

// GLOBAL: LEGO1 0x100f4570
MxAtomId* g_pz5Script = NULL;

// GLOBAL: LEGO1 0x100f4574
MxAtomId* g_introScript = NULL;

// GLOBAL: LEGO1 0x100f4578
MxAtomId* g_testScript = NULL;

// GLOBAL: LEGO1 0x100f457c
MxAtomId* g_jukeboxwScript = NULL;

// GLOBAL: LEGO1 0x100f4580
MxAtomId* g_sndAnimScript = NULL;

// GLOBAL: LEGO1 0x100f4584
MxAtomId* g_creditsScript = NULL;

// GLOBAL: LEGO1 0x100f4588
MxAtomId* g_nocdSourceName = NULL;

// FUNCTION: LEGO1 0x100528e0
// STUB: BETA10 0x100f6133
void CreateScripts()
{
	g_copterScript = new MxAtomId("\\lego\\scripts\\build\\copter", e_lowerCase2);
	g_dunecarScript = new MxAtomId("\\lego\\scripts\\build\\dunecar", e_lowerCase2);
	g_jetskiScript = new MxAtomId("\\lego\\scripts\\build\\jetski", e_lowerCase2);
	g_racecarScript = new MxAtomId("\\lego\\scripts\\build\\racecar", e_lowerCase2);
	g_carraceScript = new MxAtomId("\\lego\\scripts\\race\\carrace", e_lowerCase2);
	g_carracerScript = new MxAtomId("\\lego\\scripts\\race\\carracer", e_lowerCase2);
	g_jetraceScript = new MxAtomId("\\lego\\scripts\\race\\jetrace", e_lowerCase2);
	g_jetracerScript = new MxAtomId("\\lego\\scripts\\race\\jetracer", e_lowerCase2);
	g_isleScript = new MxAtomId("\\lego\\scripts\\isle\\isle", e_lowerCase2);
	g_elevbottScript = new MxAtomId("\\lego\\scripts\\infocntr\\elevbott", e_lowerCase2);
	g_infodoorScript = new MxAtomId("\\lego\\scripts\\infocntr\\infodoor", e_lowerCase2);
	g_infomainScript = new MxAtomId("\\lego\\scripts\\infocntr\\infomain", e_lowerCase2);
	g_infoscorScript = new MxAtomId("\\lego\\scripts\\infocntr\\infoscor", e_lowerCase2);
	g_regbookScript = new MxAtomId("\\lego\\scripts\\infocntr\\regbook", e_lowerCase2);
	g_histbookScript = new MxAtomId("\\lego\\scripts\\infocntr\\histbook", e_lowerCase2);
	g_hospitalScript = new MxAtomId("\\lego\\scripts\\hospital\\hospital", e_lowerCase2);
	g_policeScript = new MxAtomId("\\lego\\scripts\\police\\police", e_lowerCase2);
	g_garageScript = new MxAtomId("\\lego\\scripts\\garage\\garage", e_lowerCase2);
	g_act2mainScript = new MxAtomId("\\lego\\scripts\\act2\\act2main", e_lowerCase2);
	g_act3Script = new MxAtomId("\\lego\\scripts\\act3\\act3", e_lowerCase2);
	g_jukeboxScript = new MxAtomId("\\lego\\scripts\\isle\\jukebox", e_lowerCase2);
	g_pz5Script = new MxAtomId("\\lego\\scripts\\isle\\pz5", e_lowerCase2);
	g_introScript = new MxAtomId("\\lego\\scripts\\intro", e_lowerCase2);
	g_testScript = new MxAtomId("\\lego\\scripts\\test\\test", e_lowerCase2);
	g_jukeboxwScript = new MxAtomId("\\lego\\scripts\\isle\\jukeboxw", e_lowerCase2);
	g_sndAnimScript = new MxAtomId("\\lego\\scripts\\sndanim", e_lowerCase2);
	g_creditsScript = new MxAtomId("\\lego\\scripts\\credits", e_lowerCase2);
	g_nocdSourceName = new MxAtomId("\\lego\\scripts\\nocd", e_lowerCase2);
}

// FUNCTION: LEGO1 0x100530c0
void DestroyScripts()
{
	delete g_copterScript;
	delete g_dunecarScript;
	delete g_jetskiScript;
	delete g_racecarScript;
	delete g_carraceScript;
	delete g_carracerScript;
	delete g_jetraceScript;
	delete g_jetracerScript;
	delete g_isleScript;
	delete g_elevbottScript;
	delete g_infodoorScript;
	delete g_infomainScript;
	delete g_infoscorScript;
	delete g_regbookScript;
	delete g_histbookScript;
	delete g_hospitalScript;
	delete g_policeScript;
	delete g_garageScript;
	delete g_act2mainScript;
	delete g_act3Script;
	delete g_jukeboxScript;
	delete g_pz5Script;
	delete g_introScript;
	delete g_testScript;
	delete g_jukeboxwScript;
	delete g_sndAnimScript;
	delete g_creditsScript;
	delete g_nocdSourceName;

	g_copterScript = NULL;
	g_dunecarScript = NULL;
	g_jetskiScript = NULL;
	g_racecarScript = NULL;
	g_carraceScript = NULL;
	g_carracerScript = NULL;
	g_jetraceScript = NULL;
	g_jetracerScript = NULL;
	g_isleScript = NULL;
	g_elevbottScript = NULL;
	g_infodoorScript = NULL;
	g_infomainScript = NULL;
	g_infoscorScript = NULL;
	g_regbookScript = NULL;
	g_histbookScript = NULL;
	g_hospitalScript = NULL;
	g_policeScript = NULL;
	g_garageScript = NULL;
	g_act2mainScript = NULL;
	g_act3Script = NULL;
	g_jukeboxScript = NULL;
	g_pz5Script = NULL;
	g_introScript = NULL;
	g_testScript = NULL;
	g_testScript = NULL;
	g_jukeboxwScript = NULL;
	g_sndAnimScript = NULL;
	g_creditsScript = NULL;
	g_nocdSourceName = NULL;
}

// FUNCTION: LEGO1 0x10053430
const char* GetNoCD_SourceName()
{
	return g_nocdSourceName->GetInternal();
}
