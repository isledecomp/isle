#include "legoomni.h"

#include "gifmanager.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoobjectfactory.h"
#include "legoplantmanager.h"
#include "legosoundmanager.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "mxautolocker.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdsfile.h"
#include "mxomnicreateflags.h"
#include "mxomnicreateparam.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"

// 0x100f451c
MxAtomId* g_copterScript = NULL;

// 0x100f4520
MxAtomId* g_dunecarScript = NULL;

// 0x100f4524
MxAtomId* g_jetskiScript = NULL;

// 0x100f4528
MxAtomId* g_racecarScript = NULL;

// 0x100f452c
MxAtomId* g_carraceScript = NULL;

// 0x100f4530
MxAtomId* g_carracerScript = NULL;

// 0x100f4534
MxAtomId* g_jetraceScript = NULL;

// 0x100f4538
MxAtomId* g_jetracerScript = NULL;

// 0x100f453c
MxAtomId* g_isleScript = NULL;

// 0x100f4540
MxAtomId* g_elevbottScript = NULL;

// 0x100f4544
MxAtomId* g_infodoorScript = NULL;

// 0x100f4548
MxAtomId* g_infomainScript = NULL;

// 0x100f454c
MxAtomId* g_infoscorScript = NULL;

// 0x100f4550
MxAtomId* g_regbookScript = NULL;

// 0x100f4554
MxAtomId* g_histbookScript = NULL;

// 0x100f4558
MxAtomId* g_hospitalScript = NULL;

// 0x100f455c
MxAtomId* g_policeScript = NULL;

// 0x100f4560
MxAtomId* g_garageScript = NULL;

// 0x100f4564
MxAtomId* g_act2mainScript = NULL;

// 0x100f4568
MxAtomId* g_act3Script = NULL;

// 0x100f456c
MxAtomId* g_jukeboxScript = NULL;

// 0x100f4570
MxAtomId* g_pz5Script = NULL;

// 0x100f4574
MxAtomId* g_introScript = NULL;

// 0x100f4578
MxAtomId* g_testScript = NULL;

// 0x100f457c
MxAtomId* g_jukeboxwScript = NULL;

// 0x100f4580c
MxAtomId* g_sndAnimScript = NULL;

// 0x100f4584
MxAtomId* g_creditsScript = NULL;

// 0x100f4588
MxAtomId* g_nocdSourceName = NULL;

// 0x100f6718
const char* g_current = "current";

// 0x101020e8
void (*g_omniUserMessage)(const char*, int);

// OFFSET: LEGO1 0x10015700
LegoOmni* Lego()
{
	return (LegoOmni*) MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x10015710
LegoSoundManager* SoundManager()
{
	return LegoOmni::GetInstance()->GetSoundManager();
}

// OFFSET: LEGO1 0x10015720
LegoVideoManager* VideoManager()
{
	return LegoOmni::GetInstance()->GetVideoManager();
}

// OFFSET: LEGO1 0x10015730
MxBackgroundAudioManager* BackgroundAudioManager()
{
	return LegoOmni::GetInstance()->GetBackgroundAudioManager();
}

// OFFSET: LEGO1 0x10015740
LegoInputManager* InputManager()
{
	return LegoOmni::GetInstance()->GetInputManager();
}

// OFFSET: LEGO1 0x10015750
LegoControlManager* ControlManager()
{
	return LegoOmni::GetInstance()->GetInputManager()->GetControlManager();
}

// OFFSET: LEGO1 0x10015760
LegoGameState* GameState()
{
	return LegoOmni::GetInstance()->GetGameState();
}

// OFFSET: LEGO1 0x10015770
LegoAnimationManager* AnimationManager()
{
	return LegoOmni::GetInstance()->GetAnimationManager();
}

// OFFSET: LEGO1 0x10015780
LegoNavController* NavController()
{
	return LegoOmni::GetInstance()->GetNavController();
}

// OFFSET: LEGO1 0x10015790
LegoWorld* GetCurrentVehicle()
{
	return LegoOmni::GetInstance()->GetCurrentVehicle();
}

// OFFSET: LEGO1 0x100157a0
LegoWorld* GetCurrentWorld()
{
	return LegoOmni::GetInstance()->GetCurrentWorld();
}

// OFFSET: LEGO1 0x100157e0
LegoPlantManager* PlantManager()
{
	return LegoOmni::GetInstance()->GetLegoPlantManager();
}

// OFFSET: LEGO1 0x100157f0
LegoBuildingManager* BuildingManager()
{
	return LegoOmni::GetInstance()->GetLegoBuildingManager();
}

// OFFSET: LEGO1 0x10015800
GifManager* GetGifManager()
{
	return LegoOmni::GetInstance()->GetGifManager();
}

// OFFSET: LEGO1 0x100158e0
MxDSAction& GetCurrentAction()
{
	return LegoOmni::GetInstance()->GetCurrentAction();
}

// OFFSET: LEGO1 0x10015900
MxTransitionManager* TransitionManager()
{
	return LegoOmni::GetInstance()->GetTransitionManager();
}

// OFFSET: LEGO1 0x10015910
void PlayMusic(MxU32 p_index)
{
	// index is the entityid of the music in jukebox.si
	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(p_index);

	LegoOmni::GetInstance()->GetBackgroundAudioManager()->PlayMusic(action, 5, 4);
}

// OFFSET: LEGO1 0x1001a700 STUB
void FUN_1001a700()
{
	// TODO
}

// OFFSET: LEGO1 0x1003dd70 STUB
LegoROI* PickROI(MxLong, MxLong)
{
	// TODO
	return NULL;
}

// OFFSET: LEGO1 0x1003ddc0 STUB
LegoEntity* PickEntity(MxLong, MxLong)
{
	// TODO
	return NULL;
}

// OFFSET: LEGO1 0x100528e0
void RegisterScripts()
{
	g_copterScript = new MxAtomId("\\lego\\scripts\\build\\copter", LookupMode_LowerCase2);
	g_dunecarScript = new MxAtomId("\\lego\\scripts\\build\\dunecar", LookupMode_LowerCase2);
	g_jetskiScript = new MxAtomId("\\lego\\scripts\\build\\jetski", LookupMode_LowerCase2);
	g_racecarScript = new MxAtomId("\\lego\\scripts\\build\\racecar", LookupMode_LowerCase2);
	g_carraceScript = new MxAtomId("\\lego\\scripts\\race\\carrace", LookupMode_LowerCase2);
	g_carracerScript = new MxAtomId("\\lego\\scripts\\race\\carracer", LookupMode_LowerCase2);
	g_jetraceScript = new MxAtomId("\\lego\\scripts\\race\\jetrace", LookupMode_LowerCase2);
	g_jetracerScript = new MxAtomId("\\lego\\scripts\\race\\jetracer", LookupMode_LowerCase2);
	g_isleScript = new MxAtomId("\\lego\\scripts\\isle\\isle", LookupMode_LowerCase2);
	g_elevbottScript = new MxAtomId("\\lego\\scripts\\infocntr\\elevbott", LookupMode_LowerCase2);
	g_infodoorScript = new MxAtomId("\\lego\\scripts\\infocntr\\infodoor", LookupMode_LowerCase2);
	g_infomainScript = new MxAtomId("\\lego\\scripts\\infocntr\\infomain", LookupMode_LowerCase2);
	g_infoscorScript = new MxAtomId("\\lego\\scripts\\infocntr\\infoscor", LookupMode_LowerCase2);
	g_regbookScript = new MxAtomId("\\lego\\scripts\\infocntr\\regbook", LookupMode_LowerCase2);
	g_histbookScript = new MxAtomId("\\lego\\scripts\\infocntr\\histbook", LookupMode_LowerCase2);
	g_hospitalScript = new MxAtomId("\\lego\\scripts\\hospital\\hospital", LookupMode_LowerCase2);
	g_policeScript = new MxAtomId("\\lego\\scripts\\police\\police", LookupMode_LowerCase2);
	g_garageScript = new MxAtomId("\\lego\\scripts\\garage\\garage", LookupMode_LowerCase2);
	g_act2mainScript = new MxAtomId("\\lego\\scripts\\act2\\act2main", LookupMode_LowerCase2);
	g_act3Script = new MxAtomId("\\lego\\scripts\\act3\\act3", LookupMode_LowerCase2);
	g_jukeboxScript = new MxAtomId("\\lego\\scripts\\isle\\jukebox", LookupMode_LowerCase2);
	g_pz5Script = new MxAtomId("\\lego\\scripts\\isle\\pz5", LookupMode_LowerCase2);
	g_introScript = new MxAtomId("\\lego\\scripts\\intro", LookupMode_LowerCase2);
	g_testScript = new MxAtomId("\\lego\\scripts\\test\\test", LookupMode_LowerCase2);
	g_jukeboxwScript = new MxAtomId("\\lego\\scripts\\isle\\jukeboxw", LookupMode_LowerCase2);
	g_sndAnimScript = new MxAtomId("\\lego\\scripts\\sndanim", LookupMode_LowerCase2);
	g_creditsScript = new MxAtomId("\\lego\\scripts\\credits", LookupMode_LowerCase2);
	g_nocdSourceName = new MxAtomId("\\lego\\scripts\\nocd", LookupMode_LowerCase2);
}

// OFFSET: LEGO1 0x100530c0
void UnregisterScripts()
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

// OFFSET: LEGO1 0x10053430
const char* GetNoCD_SourceName()
{
	return g_nocdSourceName->GetInternal();
}

// OFFSET: LEGO1 0x10058a00
LegoOmni::LegoOmni()
{
	Init();
}

// OFFSET: LEGO1 0x10058b50
LegoOmni::~LegoOmni()
{
	Destroy();
}

// OFFSET: LEGO1 0x10058bd0
void LegoOmni::Init()
{
	MxOmni::Init();
	m_unk68 = 0;
	m_inputMgr = NULL;
	m_unk6c = 0;
	m_gifManager = NULL;
	m_unk78 = 0;
	m_currentWorld = NULL;
	m_unk80 = FALSE;
	m_currentVehicle = NULL;
	m_unkLegoSaveDataWriter = NULL;
	m_plantManager = NULL;
	m_gameState = NULL;
	m_animationManager = NULL;
	m_buildingManager = NULL;
	m_bkgAudioManager = NULL;
	m_unk13c = TRUE;
	m_transitionManager = NULL;
}

// OFFSET: LEGO1 0x10058c30 STUB
void LegoOmni::Destroy()
{
	// TODO
}

// OFFSET: LEGO1 0x10058e70
MxResult LegoOmni::Create(MxOmniCreateParam& p)
{
	MxResult result = FAILURE;
	MxAutoLocker lock(&this->m_criticalsection);

	p.CreateFlags().CreateObjectFactory(FALSE);
	p.CreateFlags().CreateVideoManager(FALSE);
	p.CreateFlags().CreateSoundManager(FALSE);
	p.CreateFlags().CreateTickleManager(FALSE);

	if (!(m_tickleManager = new MxTickleManager()))
		return FAILURE;

	if (MxOmni::Create(p) != SUCCESS)
		return FAILURE;

	m_objectFactory = new LegoObjectFactory();
	if (m_objectFactory == NULL)
		return FAILURE;

	if (m_soundManager = new LegoSoundManager()) {
		if (m_soundManager->Create(10, 0) != SUCCESS) {
			delete m_soundManager;
			m_soundManager = NULL;
			return FAILURE;
		}
	}

	if (m_videoManager = new LegoVideoManager()) {
		if (m_videoManager->Create(p.GetVideoParam(), 100, 0) != SUCCESS) {
			delete m_videoManager;
			m_videoManager = NULL;
		}
	}

	if (m_inputMgr = new LegoInputManager()) {
		if (m_inputMgr->Create(p.GetWindowHandle()) != SUCCESS) {
			delete m_inputMgr;
			m_inputMgr = NULL;
		}
	}

	// TODO: there are a few more classes here
	m_gifManager = new GifManager();
	m_plantManager = new LegoPlantManager();
	m_animationManager = new LegoAnimationManager();
	m_buildingManager = new LegoBuildingManager();
	m_gameState = new LegoGameState();
	// TODO: initialize list at m_unk78

	if (m_unk6c && m_gifManager && m_unk78 && m_plantManager && m_animationManager && m_buildingManager) {
		// TODO: initialize a bunch of MxVariables
		RegisterScripts();
		FUN_1001a700();
		// todo: another function call. in legoomni maybe?
		m_bkgAudioManager = new MxBackgroundAudioManager();
		if (m_bkgAudioManager != NULL) {
			m_transitionManager = new MxTransitionManager();
			if (m_transitionManager != NULL) {
				if (m_transitionManager->GetDDrawSurfaceFromVideoManager() == SUCCESS) {
					m_notificationManager->Register(this);
					SetAppCursor(1);
					m_gameState->SetSomeEnumState(0);
					return SUCCESS;
				}
			}
		}
	}

	return FAILURE;
}

// OFFSET: LEGO1 0x1005ac90
void LegoOmni::CreateInstance()
{
	MxOmni::DestroyInstance();
	MxOmni::SetInstance(new LegoOmni());
}

// OFFSET: LEGO1 0x1005ad10
LegoOmni* LegoOmni::GetInstance()
{
	return (LegoOmni*) MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x1005af10 STUB
void LegoOmni::RemoveWorld(const MxAtomId& p1, MxLong p2)
{
	// TODO
}

// OFFSET: LEGO1 0x1005b0c0 STUB
LegoEntity* LegoOmni::FindByEntityIdOrAtomId(const MxAtomId& p_atom, MxS32 p_entityid)
{
	// TODO
	return NULL;
}

// OFFSET: LEGO1 0x1005b1d0 STUB
MxResult LegoOmni::DeleteObject(MxDSAction& ds)
{
	// TODO
	return FAILURE;
}

// OFFSET: LEGO1 0x1005b2f0
MxEntity* LegoOmni::FindWorld(const char* p_id, MxS32 p_entityId, MxPresenter* p_presenter)
{
	LegoWorld* foundEntity = NULL;
	if (strcmpi(p_id, g_current)) {
		foundEntity = (LegoWorld*) FindByEntityIdOrAtomId(MxAtomId(p_id, LookupMode_LowerCase2), p_entityId);
	}
	else {
		foundEntity = this->m_currentWorld;
	}

	if (foundEntity != NULL) {
		foundEntity->VTable0x58(p_presenter);
	}

	return foundEntity;
}

// OFFSET: LEGO1 0x1005b3a0
void LegoOmni::NotifyCurrentEntity(MxNotificationParam* p_param)
{
	if (m_currentWorld)
		NotificationManager()->Send(m_currentWorld, p_param);
}

// OFFSET: LEGO1 0x1005b3c0
MxBool LegoOmni::DoesEntityExist(MxDSAction& ds)
{
	if (MxOmni::DoesEntityExist(ds)) {
		if (FindByEntityIdOrAtomId(ds.GetAtomId(), ds.GetObjectId()) == NULL) {
			return TRUE;
		}
	}
	return FALSE;
}

// OFFSET: LEGO1 0x1005b400 STUB
int LegoOmni::GetCurrPathInfo(LegoPathBoundary**, int&)
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x1005b560
void LegoOmni::CreateBackgroundAudio()
{
	if (m_bkgAudioManager)
		m_bkgAudioManager->Create(*g_jukeboxScript, 100);
}

// OFFSET: LEGO1 0x1005b580
MxResult LegoOmni::Start(MxDSAction* action)
{
	MxResult result = MxOmni::Start(action);
	this->m_action.SetAtomId(action->GetAtomId());
	this->m_action.SetObjectId(action->GetObjectId());
	this->m_action.SetUnknown24(action->GetUnknown24());
	return result;
}

// OFFSET: LEGO1 0x1005b5f0 STUB
MxLong LegoOmni::Notify(MxParam& p)
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x1005b640
void LegoOmni::StartTimer()
{
	MxOmni::StartTimer();
	SetAppCursor(2);
}

// OFFSET: LEGO1 0x1005b650
void LegoOmni::StopTimer()
{
	MxOmni::StopTimer();
	SetAppCursor(0);
}

// OFFSET: LEGO1 0x100acf50
MxResult Start(MxDSAction* p_dsAction)
{
	return MxOmni::GetInstance()->Start(p_dsAction);
}

// OFFSET: LEGO1 0x100b6ff0
void MakeSourceName(char* p_output, const char* p_input)
{
	const char* cln = strchr(p_input, ':');
	if (cln) {
		p_input = cln + 1;
	}

	strcpy(p_output, p_input);

	strlwr(p_output);

	char* extLoc = strstr(p_output, ".si");
	if (extLoc) {
		*extLoc = 0;
	}
}

// OFFSET: LEGO1 0x100b7050
MxBool KeyValueStringParse(char* p_outputValue, const char* p_key, const char* p_source)
{
	MxBool didMatch = FALSE;

	MxS16 len = strlen(p_source);
	char* temp = new char[len + 1];
	strcpy(temp, p_source);

	char* token = strtok(temp, ", \t\r\n:");
	while (token) {
		len -= (strlen(token) + 1);

		if (strcmpi(token, p_key) == 0) {
			if (p_outputValue && len > 0) {
				char* cur = &token[strlen(p_key)];
				cur++;
				while (*cur != ',') {
					if (*cur == ' ' || *cur == '\0' || *cur == '\t' || *cur == '\n' || *cur == '\r')
						break;
					*p_outputValue++ = *cur++;
				}
				*p_outputValue = '\0';
			}

			didMatch = TRUE;
			break;
		}

		token = strtok(NULL, ", \t\r\n:");
	}

	delete[] temp;
	return didMatch;
}

// OFFSET: LEGO1 0x100b7210
void SetOmniUserMessage(void (*p_userMsg)(const char*, int))
{
	g_omniUserMessage = p_userMsg;
}

// OFFSET: LEGO1 0x100c0280
MxDSObject* CreateStreamObject(MxDSFile* p_file, MxS16 p_ofs)
{
	char* buf;
	_MMCKINFO tmp_chunk;

	if (p_file->Seek(((MxLong*) p_file->GetBuffer())[p_ofs], 0)) {
		return NULL;
	}

	if (p_file->Read((MxU8*) &tmp_chunk.ckid, 8) == 0 && tmp_chunk.ckid == FOURCC('M', 'x', 'S', 't')) {
		if (p_file->Read((MxU8*) &tmp_chunk.ckid, 8) == 0 && tmp_chunk.ckid == FOURCC('M', 'x', 'O', 'b')) {

			buf = new char[tmp_chunk.cksize];
			if (!buf) {
				return NULL;
			}

			if (p_file->Read((MxU8*) buf, tmp_chunk.cksize) != 0) {
				return NULL;
			}

			// Save a copy so we can clean up properly, because
			// this function will alter the pointer value.
			char* copy = buf;
			MxDSObject* obj = DeserializeDSObjectDispatch(&buf, -1);
			delete[] copy;
			return obj;
		}
		return NULL;
	}

	return NULL;
}
