#include "legomain.h"

#include "3dmanager/lego3dmanager.h"
#include "islepathactor.h"
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
#include "mxdisplaysurface.h"
#include "mxdsfile.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxomnicreateflags.h"
#include "mxomnicreateparam.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"
#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(LegoOmni, 0x140)
DECOMP_SIZE_ASSERT(LegoOmni::ScriptContainer, 0x1c)
DECOMP_SIZE_ASSERT(LegoWorldList, 0x18)
DECOMP_SIZE_ASSERT(LegoWorldListCursor, 0x10)

// GLOBAL: LEGO1 0x100f6718
// STRING: LEGO1 0x100f6710
const char* g_current = "current";

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
	m_userActor = NULL;
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
		m_textureContainer->Clear();
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

	LegoPathController::Reset();

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

	if (m_scripts) {
		delete[] m_scripts;
	}

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
	LegoPathController::Init();

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
	IslePathActor::RegisterSpawnLocations();
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
	SetAppCursor(e_cursorBusy);
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
void LegoOmni::NotifyCurrentEntity(const MxNotificationParam& p_param)
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
const char* LegoOmni::GetScriptName(MxU32 p_index)
{
	for (MxS32 i = 0; i < 19; i++) {
		if (m_scripts[i].m_index == p_index) {
			return m_scripts[i].m_key;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1005b460
MxAtomId* LegoOmni::GetScriptAtom(MxU32 p_index)
{
	for (MxS32 i = 0; i < 19; i++) {
		if (m_scripts[i].m_index == p_index) {
			return m_scripts[i].m_atomId;
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
void LegoOmni::Pause()
{
	MxOmni::Pause();
	SetAppCursor(e_cursorNo);
}

// FUNCTION: LEGO1 0x1005b650
void LegoOmni::Resume()
{
	MxOmni::Resume();
	SetAppCursor(e_cursorArrow);
}
