#include "legoomni.h"

#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legocharactermanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoobjectfactory.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "legoworldlist.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "mxactionnotificationparam.h"
#include "mxautolock.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdsfile.h"
#include "mxmisc.h"
#include "mxomnicreateflags.h"
#include "mxomnicreateparam.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(LegoOmni::ScriptContainer, 0x1c)
DECOMP_SIZE_ASSERT(LegoOmni::PathContainer, 0x38)
DECOMP_SIZE_ASSERT(LegoWorldList, 0x18)
DECOMP_SIZE_ASSERT(LegoWorldListCursor, 0x10)

// GLOBAL: LEGO1 0x100f451c
MxAtomId* g_copterScript = NULL;

// GLOBAL: LEGO1 0x100f4520
MxAtomId* g_dunecarScript = NULL;

// GLOBAL: LEGO1 0x100f4524
MxAtomId* g_jetskiScript = NULL;

// GLOBAL: LEGO1 0x100f4528
MxAtomId* g_racecarScript = NULL;

// GLOBAL: LEGO1 0x100f452c
MxAtomId* g_carraceScript = NULL;

// GLOBAL: LEGO1 0x100f4530
MxAtomId* g_carracerScript = NULL;

// GLOBAL: LEGO1 0x100f4534
MxAtomId* g_jetraceScript = NULL;

// GLOBAL: LEGO1 0x100f4538
MxAtomId* g_jetracerScript = NULL;

// GLOBAL: LEGO1 0x100f453c
MxAtomId* g_isleScript = NULL;

// GLOBAL: LEGO1 0x100f4540
MxAtomId* g_elevbottScript = NULL;

// GLOBAL: LEGO1 0x100f4544
MxAtomId* g_infodoorScript = NULL;

// GLOBAL: LEGO1 0x100f4548
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

// GLOBAL: LEGO1 0x100f6718
// STRING: LEGO1 0x100f6710
const char* g_current = "current";

// GLOBAL: LEGO1 0x10102b28
LegoOmni::PathContainer g_extraPaths[29];

// FUNCTION: LEGO1 0x1001a700
void RegisterExtraPaths()
{
	g_extraPaths[0] = LegoOmni::PathContainer(0x16, g_isleScript, 0, "int35", 2, 0.6, 4, 0.4, 0x2a, 0x12);
	g_extraPaths[1] = LegoOmni::PathContainer(0x17, g_isleScript, 0, "edg00_49", 1, 0.43, 2, 0.6, 0x27, 0x12);
	g_extraPaths[2] = LegoOmni::PathContainer(0x18, g_isleScript, 0, "edg00_191", 2, 0.5, 0, 0.55, 0x26, 0x12);
	g_extraPaths[3] = LegoOmni::PathContainer(0x04, g_isleScript, 0, "int46", 0, 0.5, 2, 0.5, 0x10, 0x0b);
	g_extraPaths[4] = LegoOmni::PathContainer(0x10, g_isleScript, 0, "EDG00_46", 0, 0.95, 2, 0.19, 0x17, 0x11);
	g_extraPaths[5] = LegoOmni::PathContainer(0x11, g_isleScript, 0, "EDG00_46", 3, 0.625, 2, 0.03, 0x18, 0x11);
	g_extraPaths[6] = LegoOmni::PathContainer(0x0f, g_isleScript, 0, "EDG10_63", 0, 0.26, 1, 0.01, 0, -1);
	g_extraPaths[7] = LegoOmni::PathContainer(0x13, g_isleScript, 0, "INT15", 5, 0.65, 1, 0.68, 0x33, 0x0e);
	g_extraPaths[8] = LegoOmni::PathContainer(0x14, g_isleScript, 0, "INT16", 4, 0.1, 2, 0, 0x34, 0x0e);
	g_extraPaths[9] = LegoOmni::PathContainer(0x15, g_isleScript, 0, "INT62", 2, 0.1, 3, 0.7, 0x36, 0x0e);
	g_extraPaths[10] = LegoOmni::PathContainer(0x19, g_isleScript, 0, "INT24", 0, 0.55, 2, 0.71, 0x08, 0x0f);
	g_extraPaths[11] = LegoOmni::PathContainer(0x1c, g_isleScript, 0, "INT24", 2, 0.73, 4, 0.71, 0x0a, 0x0f);
	g_extraPaths[12] = LegoOmni::PathContainer(0x1d, g_isleScript, 0, "INT19", 0, 0.85, 1, 0.28, 0, 0x0a);
	g_extraPaths[13] = LegoOmni::PathContainer(0x1f, g_isleScript, 0, "EDG02_28", 3, 0.37, 1, 0.52, 0x0c, 0x0a);
	g_extraPaths[14] = LegoOmni::PathContainer(0x20, g_isleScript, 0, "INT33", 0, 0.88, 2, 0.74, 0x22, 0x0c);
	g_extraPaths[15] = LegoOmni::PathContainer(0x21, g_isleScript, 0, "EDG02_64", 2, 0.24, 0, 0.84, 0x23, 0x0c);
	g_extraPaths[16] = LegoOmni::PathContainer(0x28, g_isleScript, 0, "edg02_51", 2, 0.63, 3, 0.01, 0, -1);
	g_extraPaths[17] = LegoOmni::PathContainer(0x29, g_isleScript, 0, "edg02_51", 2, 0.63, 0, 0.4, 0, -1);
	g_extraPaths[18] = LegoOmni::PathContainer(0x2b, g_isleScript, 0, "edg02_35", 2, 0.8, 0, 0.2, 0, -1);
	g_extraPaths[19] = LegoOmni::PathContainer(0x2c, g_isleScript, 0, "EDG03_01", 2, 0.25, 0, 0.75, 0, -1);
	g_extraPaths[20] = LegoOmni::PathContainer(0x2d, g_isleScript, 0, "edg10_70", 3, 0.25, 0, 0.7, 0x44, -1);
	g_extraPaths[21] = LegoOmni::PathContainer(0x2a, g_isleScript, 0, "inv_05", 2, 0.75, 0, 0.19, 0, -1);
	g_extraPaths[22] = LegoOmni::PathContainer(0x30, g_act3Script, 0, "edg02_51", 2, 0.63, 0, 0.4, 0, -1);
	g_extraPaths[23] = LegoOmni::PathContainer(0x31, g_act3Script, 0, "inv_05", 2, 0.75, 0, 0.19, 0, -1);
	g_extraPaths[24] = LegoOmni::PathContainer(0x32, g_act2mainScript, 0, "EDG02_51", 0, 0.64, 1, 0.37, 0, -1);
	g_extraPaths[25] = LegoOmni::PathContainer(0x33, g_isleScript, 0, "edg02_32", 0, 0.5, 2, 0.5, 0, -1);
	g_extraPaths[26] = LegoOmni::PathContainer(0x34, g_isleScript, 0, "edg02_19", 2, 0.5, 0, 0.5, 0, -1);
	g_extraPaths[27] = LegoOmni::PathContainer(0x36, g_isleScript, 0, "int36", 0, 0.2, 4, 0.4, 0, -1);
	g_extraPaths[28] = LegoOmni::PathContainer(0x37, g_isleScript, 0, "edg02_50", 2, 0.8, 1, 0.3, 0, -1);
}

// FUNCTION: LEGO1 0x1003dd70
LegoROI* PickROI(MxLong p_a, MxLong p_b)
{
	return (LegoROI*) VideoManager()->Get3DManager()->GetLego3DView()->Pick(p_a, p_b);
}

// STUB: LEGO1 0x1003ddc0
LegoEntity* PickEntity(MxLong, MxLong)
{
	// TODO
	return NULL;
}

// FUNCTION: LEGO1 0x100528e0
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

// FUNCTION: LEGO1 0x10058a00
LegoOmni::LegoOmni()
{
	Init();
}

// FUNCTION: LEGO1 0x10058b50
LegoOmni::~LegoOmni()
{
	Destroy();
}

// FUNCTION: LEGO1 0x10058bd0
void LegoOmni::Init()
{
	MxOmni::Init();
	m_scripts = NULL;
	m_inputManager = NULL;
	m_viewLODListManager = NULL;
	m_textureContainer = NULL;
	m_worldList = NULL;
	m_currentWorld = NULL;
	m_exit = FALSE;
	m_currentActor = NULL;
	m_characterManager = NULL;
	m_plantManager = NULL;
	m_gameState = NULL;
	m_animationManager = NULL;
	m_buildingManager = NULL;
	m_bkgAudioManager = NULL;
	m_unk0x13c = TRUE;
	m_transitionManager = NULL;
}

// FUNCTION: LEGO1 0x10058c30
void LegoOmni::Destroy()
{
	AUTOLOCK(m_criticalSection);

	m_notificationManager->Unregister(this);

	if (m_worldList) {
		delete m_worldList;
		m_worldList = NULL;
	}

	if (m_gameState) {
		delete m_gameState;
		m_gameState = NULL;
	}

	if (m_animationManager) {
		delete m_animationManager;
		m_animationManager = NULL;
	}

	if (m_characterManager) {
		delete m_characterManager;
		m_characterManager = NULL;
	}

	if (m_plantManager) {
		delete m_plantManager;
		m_plantManager = NULL;
	}

	if (m_buildingManager) {
		delete m_buildingManager;
		m_buildingManager = NULL;
	}

	if (m_textureContainer) {
		delete m_textureContainer;
		m_textureContainer = NULL;
	}

	if (m_viewLODListManager) {
		delete m_viewLODListManager;
		m_viewLODListManager = NULL;
	}

	if (m_inputManager) {
		delete m_inputManager;
		m_inputManager = NULL;
	}

	if (m_inputManager) {
		delete m_inputManager;
		m_inputManager = NULL;
	}

	// todo FUN_10046de0

	if (m_bkgAudioManager) {
		m_bkgAudioManager->Stop();

		delete m_bkgAudioManager;
		m_bkgAudioManager = NULL;
	}

	if (m_transitionManager) {
		delete m_transitionManager;
		m_transitionManager = NULL;
	}

	m_action.ClearAtom();
	DestroyScripts();

	delete[] m_scripts;

	MxOmni::Destroy();
}

// FUNCTION: LEGO1 0x10058e70
MxResult LegoOmni::Create(MxOmniCreateParam& p_param)
{
	MxResult result = FAILURE;
	AUTOLOCK(m_criticalSection);

	p_param.CreateFlags().CreateObjectFactory(FALSE);
	p_param.CreateFlags().CreateVideoManager(FALSE);
	p_param.CreateFlags().CreateSoundManager(FALSE);
	p_param.CreateFlags().CreateTickleManager(FALSE);

	if (!(m_tickleManager = new MxTickleManager())) {
		goto done;
	}

	if (MxOmni::Create(p_param) != SUCCESS) {
		goto done;
	}

	if (!(m_objectFactory = new LegoObjectFactory())) {
		goto done;
	}

	if (!(m_soundManager = new LegoSoundManager()) || m_soundManager->Create(10, 0) != SUCCESS) {
		delete m_soundManager;
		m_soundManager = NULL;
		goto done;
	}

	if (!(m_videoManager = new LegoVideoManager()) ||
		m_videoManager->Create(p_param.GetVideoParam(), 100, 0) != SUCCESS) {
		delete m_videoManager;
		m_videoManager = NULL;
		goto done;
	}

	if (!(m_inputManager = new LegoInputManager()) || m_inputManager->Create(p_param.GetWindowHandle()) != SUCCESS) {
		delete m_inputManager;
		m_inputManager = NULL;
		goto done;
	}

	m_viewLODListManager = new ViewLODListManager();
	m_textureContainer = new LegoTextureContainer();
	m_textureContainer->SetOwnership(FALSE);
	// FUN_10046c10

	m_characterManager = new LegoCharacterManager();
	m_plantManager = new LegoPlantManager();
	m_animationManager = new LegoAnimationManager();
	m_buildingManager = new LegoBuildingManager();
	m_gameState = new LegoGameState();
	m_worldList = new LegoWorldList(TRUE);

	if (!m_viewLODListManager || !m_textureContainer || !m_worldList || !m_characterManager || !m_plantManager ||
		!m_animationManager || !m_buildingManager) {
		goto done;
	}

	MxVariable* variable;

	if (!(variable = new VisibilityVariable())) {
		goto done;
	}
	m_variableTable->SetVariable(variable);

	if (!(variable = new CameraLocationVariable())) {
		goto done;
	}
	m_variableTable->SetVariable(variable);

	if (!(variable = new CursorVariable())) {
		goto done;
	}
	m_variableTable->SetVariable(variable);

	if (!(variable = new WhoAmIVariable())) {
		goto done;
	}
	m_variableTable->SetVariable(variable);

	CreateScripts();
	RegisterExtraPaths();
	result = RegisterScripts();

	if (result != SUCCESS) {
		goto done;
	}

	if (!(m_bkgAudioManager = new MxBackgroundAudioManager())) {
		goto done;
	}

	if (!(m_transitionManager = new MxTransitionManager())) {
		goto done;
	}

	if (m_transitionManager->GetDDrawSurfaceFromVideoManager() != SUCCESS) {
		goto done;
	}

	m_notificationManager->Register(this);
	SetAppCursor(1);
	m_gameState->SetCurrentAct(LegoGameState::e_act1);

	result = SUCCESS;

done:
	return result;
}

// FUNCTION: LEGO1 0x1005a5f0
MxResult LegoOmni::RegisterScripts()
{
	m_scripts = new ScriptContainer[19];

	if (!m_scripts) {
		return FAILURE;
	}

	m_scripts[0] = ScriptContainer();
	m_scripts[1] = ScriptContainer(0, "ACT1", g_isleScript);
	m_scripts[2] = ScriptContainer(1, "IMAIN", g_infomainScript);
	m_scripts[3] = ScriptContainer(2, "ICUBE", g_infoscorScript);
	m_scripts[4] = ScriptContainer(3, "IREG", g_regbookScript);
	m_scripts[5] = ScriptContainer(4, "IELEV", g_elevbottScript);
	m_scripts[6] = ScriptContainer(5, "IISLE", g_infodoorScript);
	m_scripts[7] = ScriptContainer(6, "HOSP", g_hospitalScript);
	m_scripts[8] = ScriptContainer(7, "POLICE", g_policeScript);
	m_scripts[9] = ScriptContainer(8, "GMAIN", g_garageScript);
	m_scripts[10] = ScriptContainer(9, "BLDH", g_copterScript);
	m_scripts[11] = ScriptContainer(10, "BLDD", g_dunecarScript);
	m_scripts[12] = ScriptContainer(11, "BLDJ", g_jetskiScript);
	m_scripts[13] = ScriptContainer(12, "BLDR", g_racecarScript);
	m_scripts[14] = ScriptContainer(13, "RACC", g_carraceScript);
	m_scripts[15] = ScriptContainer(14, "RACJ", g_jetraceScript);
	m_scripts[16] = ScriptContainer(15, "ACT2", g_act2mainScript);
	m_scripts[17] = ScriptContainer(16, "ACT3", g_act3Script);
	m_scripts[18] = ScriptContainer(17, "TEST", g_testScript);

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005ac90
void LegoOmni::CreateInstance()
{
	MxOmni::DestroyInstance();
	MxOmni::SetInstance(new LegoOmni());
}

// FUNCTION: LEGO1 0x1005ad10
LegoOmni* LegoOmni::GetInstance()
{
	return (LegoOmni*) MxOmni::GetInstance();
}

// FUNCTION: LEGO1 0x1005ad20
void LegoOmni::AddWorld(LegoWorld* p_world)
{
	m_worldList->Append(p_world);
}

// FUNCTION: LEGO1 0x1005adb0
void LegoOmni::DeleteWorld(LegoWorld* p_world)
{
	if (m_worldList) {
		LegoWorldListCursor cursor(m_worldList);

		if (cursor.Find(p_world)) {
			cursor.Detach();

			if (m_currentWorld == p_world) {
				m_currentWorld = NULL;
			}

			delete p_world;
		}
	}
}

// FUNCTION: LEGO1 0x1005af10
void LegoOmni::RemoveWorld(const MxAtomId& p_atom, MxLong p_objectId)
{
	if (m_worldList) {
		LegoWorldListCursor a(m_worldList);
		LegoWorldListCursor b(m_worldList);
		LegoWorld* world;

		a.Head();
		while (a.Current(world)) {
			b = a;
			b.Next();

			if ((p_objectId == -1 || world->GetEntityId() == p_objectId) &&
				(!p_atom.GetInternal() || world->GetAtom() == p_atom)) {
				a.Detach();
				delete world;
			}

			a = b;
		}
	}
}

// FUNCTION: LEGO1 0x1005b0c0
LegoWorld* LegoOmni::FindWorld(const MxAtomId& p_atom, MxS32 p_entityid)
{
	if (m_worldList) {
		LegoWorldListCursor cursor(m_worldList);
		LegoWorld* world;

		while (cursor.Next(world)) {
			if ((p_entityid == -1 || world->GetEntityId() == p_entityid) &&
				(!p_atom.GetInternal() || world->GetAtom() == p_atom)) {
				return world;
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1005b1d0
void LegoOmni::DeleteObject(MxDSAction& p_dsAction)
{
	if (p_dsAction.GetAtomId().GetInternal() != NULL) {
		LegoWorld* world = FindWorld(p_dsAction.GetAtomId(), p_dsAction.GetObjectId());
		if (world) {
			DeleteWorld(world);
			return;
		}

		if (m_currentWorld != NULL) {
			MxCore* entity = m_currentWorld->Find(p_dsAction.GetAtomId(), p_dsAction.GetObjectId());
			if (entity) {
				m_currentWorld->Remove(entity);

				if (entity->IsA("MxPresenter")) {
					Streamer()->FUN_100b98f0(((MxPresenter*) entity)->GetAction());
					((MxPresenter*) entity)->EndAction();
				}
				else {
					delete entity;
				}
				return;
			}
		}
	}
	MxOmni::DeleteObject(p_dsAction);
}

// FUNCTION: LEGO1 0x1005b270
LegoROI* LegoOmni::FindROI(const char* p_name)
{
	ViewManager* viewManager = GetVideoManager()->Get3DManager()->GetLego3DView()->GetViewManager();
	const CompoundObject& rois = viewManager->GetROIs();

	if (p_name != NULL && *p_name != '\0' && rois.size() > 0) {
		for (CompoundObject::const_iterator it = rois.begin(); it != rois.end(); it++) {
			LegoROI* roi = (LegoROI*) *it;
			const char* name = roi->GetName();

			if (name != NULL) {
				if (!strcmpi(name, p_name)) {
					return roi;
				}
			}
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1005b2f0
MxEntity* LegoOmni::AddToWorld(const char* p_id, MxS32 p_entityId, MxPresenter* p_presenter)
{
	LegoWorld* world = NULL;

	if (strcmpi(p_id, g_current)) {
		world = FindWorld(MxAtomId(p_id, e_lowerCase2), p_entityId);
	}
	else {
		world = this->m_currentWorld;
	}

	if (world != NULL) {
		world->Add(p_presenter);
	}

	return world;
}

// FUNCTION: LEGO1 0x1005b3a0
void LegoOmni::NotifyCurrentEntity(MxNotificationParam* p_param)
{
	if (m_currentWorld) {
		NotificationManager()->Send(m_currentWorld, p_param);
	}
}

// FUNCTION: LEGO1 0x1005b3c0
MxBool LegoOmni::DoesEntityExist(MxDSAction& p_dsAction)
{
	if (MxOmni::DoesEntityExist(p_dsAction)) {
		if (FindWorld(p_dsAction.GetAtomId(), p_dsAction.GetObjectId()) == NULL) {
			return TRUE;
		}
	}
	return FALSE;
}

// FUNCTION: LEGO1 0x1005b400
MxS32 LegoOmni::GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value)
{
	if (::CurrentWorld() == NULL) {
		return FAILURE;
	}

	return ::CurrentWorld()->GetCurrPathInfo(p_path, p_value);
}

// FUNCTION: LEGO1 0x1005b430
const char* LegoOmni::FindScript(MxU32 p_index)
{
	for (MxS32 i = 0; i < 19; i++) {
		if (m_scripts[i].m_index == p_index) {
			return m_scripts[i].m_key;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1005b490
MxS32 LegoOmni::GetScriptIndex(const char* p_key)
{
	for (MxS32 i = 0; i < 19; i++) {
		if ((MxS32) &m_scripts[i] != -4 && !strcmpi(m_scripts[i].GetKey(), p_key)) {
			return m_scripts[i].GetIndex();
		}
	}

	return -1;
}

// FUNCTION: LEGO1 0x1005b4f0
void LegoOmni::FUN_1005b4f0(MxBool p_disable, MxU16 p_flags)
{
	if (p_disable) {
		if (p_flags & c_disableInput) {
			m_inputManager->DisableInputProcessing();
		}

		if (p_flags & c_disable3d) {
			((LegoVideoManager*) m_videoManager)->SetRender3D(FALSE);
		}

		if (p_flags & c_clearScreen) {
			m_videoManager->GetDisplaySurface()->ClearScreen();
		}
	}
	else {
		m_inputManager->EnableInputProcessing();
		((LegoVideoManager*) m_videoManager)->SetRender3D(TRUE);
		((LegoVideoManager*) m_videoManager)->UpdateView(0, 0, 0, 0);
	}
}

// FUNCTION: LEGO1 0x1005b560
void LegoOmni::CreateBackgroundAudio()
{
	if (m_bkgAudioManager) {
		m_bkgAudioManager->Create(*g_jukeboxScript, 100);
	}
}

// FUNCTION: LEGO1 0x1005b580
MxResult LegoOmni::Start(MxDSAction* p_dsAction)
{
	MxResult result = MxOmni::Start(p_dsAction);
	this->m_action.SetAtomId(p_dsAction->GetAtomId());
	this->m_action.SetObjectId(p_dsAction->GetObjectId());
	this->m_action.SetUnknown24(p_dsAction->GetUnknown24());
	return result;
}

// FUNCTION: LEGO1 0x1005b5c0
void LegoOmni::DeleteAction()
{
	if (m_action.GetObjectId() != -1) {
		DeleteObject(m_action);
		m_action.SetObjectId(-1);
	}
}

// FUNCTION: LEGO1 0x1005b5f0
MxLong LegoOmni::Notify(MxParam& p_param)
{
	MxBool isCD = FALSE;

	if (((MxNotificationParam&) p_param).GetType() == c_notificationEndAction &&
		((MxActionNotificationParam&) p_param).GetAction()->GetAtomId() == *g_nocdSourceName) {
		isCD = TRUE;
	}

	MxLong result = MxOmni::Notify(p_param);
	if (isCD) {
		// Exit the game if nocd.si ended
		CloseMainWindow();
	}

	return result;
}

// FUNCTION: LEGO1 0x1005b640
void LegoOmni::StartTimer()
{
	MxOmni::StartTimer();
	SetAppCursor(2);
}

// FUNCTION: LEGO1 0x1005b650
void LegoOmni::StopTimer()
{
	MxOmni::StopTimer();
	SetAppCursor(0);
}
