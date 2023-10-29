#include "legoomni.h"

#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoobjectfactory.h"
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

// 0x100f4588
MxAtomId* g_nocdSourceName = NULL;

// 0x100f456c
MxAtomId* g_jukeboxScript = NULL;

// 0x101020e8
void (*g_omniUserMessage)(const char*, int);

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

// OFFSET: LEGO1 0x1005b560
void LegoOmni::CreateBackgroundAudio()
{
	if (m_bkgAudioManager)
		m_bkgAudioManager->Create(*g_jukeboxScript, 100);
}

// OFFSET: LEGO1 0x1005af10 STUB
void LegoOmni::RemoveWorld(const MxAtomId& p1, MxLong p2)
{
	// TODO
}

// OFFSET: LEGO1 0x1005b400 STUB
int LegoOmni::GetCurrPathInfo(LegoPathBoundary**, int&)
{
	// TODO
	return 0;
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

// OFFSET: LEGO1 0x100acf50
MxResult Start(MxDSAction* p_dsAction)
{
	return MxOmni::GetInstance()->Start(p_dsAction);
}

// OFFSET: LEGO1 0x1005ad10
LegoOmni* LegoOmni::GetInstance()
{
	return (LegoOmni*) MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x1005ac90
void LegoOmni::CreateInstance()
{
	MxOmni::DestroyInstance();
	MxOmni::SetInstance(new LegoOmni());
}

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

// OFFSET: LEGO1 0x10015900
MxTransitionManager* TransitionManager()
{
	return LegoOmni::GetInstance()->GetTransitionManager();
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

// OFFSET: LEGO1 0x10053430
const char* GetNoCD_SourceName()
{
	return g_nocdSourceName->GetInternal();
}

// OFFSET: LEGO1 0x1005b5f0
MxLong LegoOmni::Notify(MxParam& p)
{
	// TODO
	return 0;
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

	m_gameState = new LegoGameState();
	m_bkgAudioManager = new MxBackgroundAudioManager();

	SetAppCursor(1);

	result = SUCCESS;
	return result;
}

// OFFSET: LEGO1 0x10058c30 STUB
void LegoOmni::Destroy()
{
	// TODO
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

// OFFSET: LEGO1 0x1005b1d0 STUB
MxResult LegoOmni::DeleteObject(MxDSAction& ds)
{
	// TODO
	return FAILURE;
}

// OFFSET: LEGO1 0x1005b3c0 STUB
MxBool LegoOmni::DoesEntityExist(MxDSAction& ds)
{
	// TODO
	return TRUE;
}

// OFFSET: LEGO1 0x1005b2f0 STUB
int LegoOmni::Vtable0x30(char*, int, MxCore*)
{
	// TODO
	return 0;
}

// OFFSET: LEGO1 0x1005b3a0
void LegoOmni::NotifyCurrentEntity(MxNotificationParam* p_param)
{
	if (m_currentWorld)
		NotificationManager()->Send(m_currentWorld, p_param);
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
