#include "mxomni.h"

#include "mxatomidcounter.h"
#include "mxautolocker.h"
#include "mxeventmanager.h"
#include "mxmusicmanager.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxomnicreateparam.h"
#include "mxsoundmanager.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxvideomanager.h"

// 0x101015b8
char g_hdPath[1024];

// 0x101019b8
char g_cdPath[1024];

// 0x10101db8
MxBool g_use3dSound;

// 0x101015b0
MxOmni* MxOmni::g_instance = NULL;

// OFFSET: LEGO1 0x100159e0
void DeleteObjects(MxAtomId* p_id, MxS32 p_first, MxS32 p_last)
{
	MxDSAction action;

	action.SetAtomId(*p_id);
	action.SetUnknown24(-2);

	for (MxS32 l_first = p_first, l_last = p_last; l_first <= l_last; l_first++) {
		action.SetObjectId(l_first);
		DeleteObject(action);
	}
}

// OFFSET: LEGO1 0x10058a90
MxBool MxOmni::IsTimerRunning()
{
	return m_timerRunning;
}

// OFFSET: LEGO1 0x100acea0
MxObjectFactory* ObjectFactory()
{
	return MxOmni::GetInstance()->GetObjectFactory();
}

// OFFSET: LEGO1 0x100aceb0
MxNotificationManager* NotificationManager()
{
	return MxOmni::GetInstance()->GetNotificationManager();
}

// OFFSET: LEGO1 0x100acec0
MxTickleManager* TickleManager()
{
	return MxOmni::GetInstance()->GetTickleManager();
}

// OFFSET: LEGO1 0x100aced0
MxTimer* Timer()
{
	return MxOmni::GetInstance()->GetTimer();
}

// OFFSET: LEGO1 0x100acee0
MxAtomIdCounterSet* AtomIdCounterSet()
{
	return MxOmni::GetInstance()->GetAtomIdCounterSet();
}

// OFFSET: LEGO1 0x100acef0
MxStreamer* Streamer()
{
	return MxOmni::GetInstance()->GetStreamer();
}

// OFFSET: LEGO1 0x100acf00
MxSoundManager* MSoundManager()
{
	return MxOmni::GetInstance()->GetSoundManager();
}

// OFFSET: LEGO1 0x100acf10
MxVideoManager* MVideoManager()
{
	return MxOmni::GetInstance()->GetVideoManager();
}

// OFFSET: LEGO1 0x100acf20
MxVariableTable* VariableTable()
{
	return MxOmni::GetInstance()->GetVariableTable();
}

// OFFSET: LEGO1 0x100acf30
MxMusicManager* MusicManager()
{
	return MxOmni::GetInstance()->GetMusicManager();
}

// OFFSET: LEGO1 0x100acf40
MxEventManager* EventManager()
{
	return MxOmni::GetInstance()->GetEventManager();
}

// OFFSET: LEGO1 0x100acf70
MxResult DeleteObject(MxDSAction& p_dsAction)
{
	return MxOmni::GetInstance()->DeleteObject(p_dsAction);
}

// OFFSET: LEGO1 0x100aef10
MxOmni::MxOmni()
{
	Init();
}

// OFFSET: LEGO1 0x100aefb0
MxEntity* MxOmni::FindWorld(const char*, MxS32, MxPresenter*)
{
	return NULL;
}

// OFFSET: LEGO1 0x100aefc0
void MxOmni::NotifyCurrentEntity(MxNotificationParam* p_param)
{
}

// OFFSET: LEGO1 0x100aeff0
MxOmni::~MxOmni()
{
	Destroy();
}

// OFFSET: LEGO1 0x100af080
void MxOmni::Init()
{
	m_windowHandle = NULL;
	m_objectFactory = NULL;
	m_variableTable = NULL;
	m_tickleManager = NULL;
	m_notificationManager = NULL;
	m_videoManager = NULL;
	m_soundManager = NULL;
	m_musicManager = NULL;
	m_eventManager = NULL;
	m_timer = NULL;
	m_streamer = NULL;
	m_atomIdCounterSet = NULL;
	m_timerRunning = NULL;
}

// OFFSET: LEGO1 0x100af0b0
void MxOmni::SetInstance(MxOmni* instance)
{
	g_instance = instance;
}

// OFFSET: LEGO1 0x100af0c0
MxResult MxOmni::Create(MxOmniCreateParam& p)
{
	MxResult result = FAILURE;

	if (!(m_atomIdCounterSet = new MxAtomIdCounterSet()))
		goto done;

	m_mediaPath = p.GetMediaPath();
	m_windowHandle = p.GetWindowHandle();

	if (p.CreateFlags().CreateObjectFactory()) {
		if (!(m_objectFactory = new MxObjectFactory()))
			goto done;
	}

	if (p.CreateFlags().CreateVariableTable()) {
		if (!(m_variableTable = new MxVariableTable()))
			goto done;
	}

	if (p.CreateFlags().CreateTimer()) {
		if (!(m_timer = new MxTimer()))
			goto done;
	}

	if (p.CreateFlags().CreateTickleManager()) {
		if (!(m_tickleManager = new MxTickleManager()))
			goto done;
	}

	if (p.CreateFlags().CreateNotificationManager()) {
		if (m_notificationManager = new MxNotificationManager()) {
			if (m_notificationManager->Create(100, 0) != SUCCESS)
				goto done;
		}
		else
			goto done;
	}

	if (p.CreateFlags().CreateStreamer()) {
		if (!(m_streamer = new MxStreamer()) || m_streamer->Create() != SUCCESS)
			goto done;
	}

	if (p.CreateFlags().CreateVideoManager()) {
		if (m_videoManager = new MxVideoManager()) {
			if (m_videoManager->Create(p.GetVideoParam(), 100, 0) != SUCCESS) {
				delete m_videoManager;
				m_videoManager = NULL;
			}
		}
	}

	if (p.CreateFlags().CreateSoundManager()) {
		if (m_soundManager = new MxSoundManager()) {
			if (m_soundManager->Create(10, 0) != SUCCESS) {
				delete m_soundManager;
				m_soundManager = NULL;
			}
		}
	}

	if (p.CreateFlags().CreateMusicManager()) {
		if (m_musicManager = new MxMusicManager()) {
			if (m_musicManager->Create(50, 0) != SUCCESS) {
				delete m_musicManager;
				m_musicManager = NULL;
			}
		}
	}

	if (p.CreateFlags().CreateEventManager()) {
		if (m_eventManager = new MxEventManager()) {
			if (m_eventManager->Create(50, 0) != SUCCESS) {
				delete m_eventManager;
				m_eventManager = NULL;
			}
		}
	}

	result = SUCCESS;
done:
	if (result != SUCCESS)
		Destroy();

	return result;
}

// OFFSET: LEGO1 0x100afe90
void MxOmni::Destroy()
{
	{
		MxDSAction action;
		action.SetObjectId(-1);
		action.SetUnknown24(-2);
		DeleteObject(action);
	}

	// TODO: private members
	if (m_notificationManager) {
		while (m_notificationManager->GetQueue()) {
			if (m_notificationManager->GetQueue()->size() == 0)
				break;
			m_notificationManager->Tickle();
		}

		m_notificationManager->SetActive(FALSE);
	}

	delete m_eventManager;
	delete m_soundManager;
	delete m_musicManager;
	delete m_videoManager;
	delete m_streamer;
	delete m_timer;
	delete m_objectFactory;
	delete m_variableTable;
	delete m_notificationManager;
	delete m_tickleManager;

	// There could be a tree/iterator function that does this inline
	if (m_atomIdCounterSet) {
		while (!m_atomIdCounterSet->empty()) {
			// Pop each node and delete its value
			MxAtomIdCounterSet::iterator begin = m_atomIdCounterSet->begin();
			MxAtomIdCounter* value = *begin;
			m_atomIdCounterSet->erase(begin);
			delete value;
		}
		delete m_atomIdCounterSet;
	}
	Init();
}

// OFFSET: LEGO1 0x100b0090
MxResult MxOmni::Start(MxDSAction* p_dsAction)
{
	MxResult result = FAILURE;
	if (p_dsAction->GetAtomId().GetInternal() != NULL && p_dsAction->GetObjectId() != -1 && m_streamer != NULL) {
		result = m_streamer->FUN_100b99b0(p_dsAction);
	}

	return result;
}

// OFFSET: LEGO1 0x100b00c0 STUB
MxResult MxOmni::DeleteObject(MxDSAction& p_dsAction)
{
	// TODO
	return FAILURE;
}

// OFFSET: LEGO1 0x100b00e0 STUB
void MxOmni::Vtable0x2c()
{
	// TODO
}

// OFFSET: LEGO1 0x100b0680
MxOmni* MxOmni::GetInstance()
{
	return g_instance;
}

// OFFSET: LEGO1 0x100b0690
void MxOmni::DestroyInstance()
{
	if (g_instance != NULL) {
		delete g_instance;
		g_instance = NULL;
	}
}

// OFFSET: LEGO1 0x100b07f0
MxLong MxOmni::Notify(MxParam& p)
{
	MxAutoLocker lock(&this->m_criticalsection);

	if (((MxNotificationParam&) p).GetNotification() != c_notificationEndAction)
		return 0;

	return HandleNotificationType2(p);
}

// OFFSET: LEGO1 0x100b0880 STUB
MxResult MxOmni::HandleNotificationType2(MxParam& p_param)
{
	// TODO STUB
	return FAILURE;
}

// OFFSET: LEGO1 0x100b0900
const char* MxOmni::GetHD()
{
	return g_hdPath;
}

// OFFSET: LEGO1 0x100b0910
void MxOmni::SetHD(const char* p_hd)
{
	strcpy(g_hdPath, p_hd);
}

// OFFSET: LEGO1 0x100b0940
const char* MxOmni::GetCD()
{
	return g_cdPath;
}

// OFFSET: LEGO1 0x100b0950
void MxOmni::SetCD(const char* p_cd)
{
	strcpy(g_cdPath, p_cd);
}

// OFFSET: LEGO1 0x100b0980
MxBool MxOmni::IsSound3D()
{
	return g_use3dSound;
}

// OFFSET: LEGO1 0x100b0990
void MxOmni::SetSound3D(MxBool p_3dsound)
{
	g_use3dSound = p_3dsound;
}

// OFFSET: LEGO1 0x100b09a0
MxBool MxOmni::DoesEntityExist(MxDSAction& p_dsAction)
{
	if (m_streamer->FUN_100b9b30(p_dsAction)) {
		MxNotificationPtrList* queue = m_notificationManager->GetQueue();

		if (!queue || queue->size() == 0)
			return TRUE;
	}
	return FALSE;
}

// OFFSET: LEGO1 0x100b09d0
void MxOmni::StartTimer()
{
	if (m_timerRunning == FALSE && m_timer != NULL && m_soundManager != NULL) {
		m_timer->Start();
		m_soundManager->vtable0x34();
		m_timerRunning = TRUE;
	}
}

// OFFSET: LEGO1 0x100b0a00
void MxOmni::StopTimer()
{
	if (m_timerRunning != FALSE && m_timer != NULL && m_soundManager != NULL) {
		m_timer->Stop();
		m_soundManager->vtable0x38();
		m_timerRunning = FALSE;
	}
}
