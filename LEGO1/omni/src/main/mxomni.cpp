#include "mxomni.h"

#include "mxactionnotificationparam.h"
#include "mxatom.h"
#include "mxautolock.h"
#include "mxdsmultiaction.h"
#include "mxeventmanager.h"
#include "mxmisc.h"
#include "mxmusicmanager.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxomnicreateparam.h"
#include "mxpresenter.h"
#include "mxsoundmanager.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxvariabletable.h"
#include "mxvideomanager.h"

// GLOBAL: LEGO1 0x101015b8
char g_hdPath[1024] = "";

// GLOBAL: LEGO1 0x101019b8
char g_cdPath[1024] = "E:";

// GLOBAL: LEGO1 0x10101db8
MxBool g_use3dSound = FALSE;

// GLOBAL: LEGO1 0x101015b0
MxOmni* MxOmni::g_instance = NULL;

// FUNCTION: LEGO1 0x100aef10
MxOmni::MxOmni()
{
	Init();
}

// FUNCTION: LEGO1 0x100aefb0
MxEntity* MxOmni::AddToWorld(const char*, MxS32, MxPresenter*)
{
	return NULL;
}

// FUNCTION: LEGO1 0x100aefc0
void MxOmni::NotifyCurrentEntity(const MxNotificationParam& p_param)
{
}

// FUNCTION: LEGO1 0x100aeff0
MxOmni::~MxOmni()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100af080
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
	m_atomSet = NULL;
	m_paused = FALSE;
}

// FUNCTION: LEGO1 0x100af0b0
void MxOmni::SetInstance(MxOmni* p_instance)
{
	g_instance = p_instance;
}

// FUNCTION: LEGO1 0x100af0c0
// FUNCTION: BETA10 0x1012f3ff
MxResult MxOmni::Create(MxOmniCreateParam& p_param)
{
	MxResult result = FAILURE;

	if (!(m_atomSet = new MxAtomSet())) {
		goto done;
	}

	m_mediaPath = p_param.GetMediaPath();
	m_windowHandle = p_param.GetWindowHandle();

	if (p_param.CreateFlags().CreateObjectFactory()) {
		if (!(m_objectFactory = new MxObjectFactory())) {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateVariableTable()) {
		if (!(m_variableTable = new MxVariableTable())) {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateTimer()) {
		if (!(m_timer = new MxTimer())) {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateTickleManager()) {
		if (!(m_tickleManager = new MxTickleManager())) {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateNotificationManager()) {
		if ((m_notificationManager = new MxNotificationManager())) {
			if (m_notificationManager->Create(100, 0) != SUCCESS) {
				goto done;
			}
		}
		else {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateStreamer()) {
		if (!(m_streamer = new MxStreamer()) || m_streamer->Create() != SUCCESS) {
			goto done;
		}
	}

	if (p_param.CreateFlags().CreateVideoManager()) {
		if ((m_videoManager = new MxVideoManager())) {
			if (m_videoManager->Create(p_param.GetVideoParam(), 100, 0) != SUCCESS) {
				delete m_videoManager;
				m_videoManager = NULL;
			}
		}
	}

	if (p_param.CreateFlags().CreateSoundManager()) {
		if ((m_soundManager = new MxSoundManager())) {
			if (m_soundManager->Create(10, 0) != SUCCESS) {
				delete m_soundManager;
				m_soundManager = NULL;
			}
		}
	}

	if (p_param.CreateFlags().CreateMusicManager()) {
		if ((m_musicManager = new MxMusicManager())) {
			if (m_musicManager->Create(50, 0) != SUCCESS) {
				delete m_musicManager;
				m_musicManager = NULL;
			}
		}
	}

	if (p_param.CreateFlags().CreateEventManager()) {
		if ((m_eventManager = new MxEventManager())) {
			if (m_eventManager->Create(50, 0) != SUCCESS) {
				delete m_eventManager;
				m_eventManager = NULL;
			}
		}
	}

	result = SUCCESS;

done:
	if (result != SUCCESS) {
		Destroy();
	}

	return result;
}

// FUNCTION: LEGO1 0x100afe90
// FUNCTION: BETA10 0x1012fe5b
void MxOmni::Destroy()
{
	{
		MxDSAction action;
		action.SetObjectId(-1);
		action.SetUnknown24(-2);
		DeleteObject(action);
	}

	if (m_notificationManager) {
		while (!m_notificationManager->IsEmpty()) {
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

	if (m_atomSet) {
		while (m_atomSet->size() != 0) {
			// Pop each node and delete its value
			MxAtomSet::iterator begin = m_atomSet->begin();
			MxAtom* value = *begin;
			m_atomSet->erase(begin);
			delete value;
		}

		delete m_atomSet;
	}

	Init();
}

// FUNCTION: LEGO1 0x100b0090
MxResult MxOmni::Start(MxDSAction* p_dsAction)
{
	MxResult result = FAILURE;
	if (p_dsAction->GetAtomId().GetInternal() != NULL && p_dsAction->GetObjectId() != -1 && m_streamer != NULL) {
		result = m_streamer->FUN_100b99b0(p_dsAction);
	}

	return result;
}

// FUNCTION: LEGO1 0x100b00c0
void MxOmni::DeleteObject(MxDSAction& p_dsAction)
{
	if (m_streamer != NULL) {
		m_streamer->DeleteObject(&p_dsAction);
	}
}

// FUNCTION: LEGO1 0x100b00e0
MxResult MxOmni::CreatePresenter(MxStreamController* p_controller, MxDSAction& p_action)
{
	MxResult result = FAILURE;
	const char* name = PresenterNameDispatch(p_action);
	MxPresenter* object = (MxPresenter*) m_objectFactory->Create(name);

	if (object) {
		if (object->AddToManager() == SUCCESS) {
			MxPresenter* sender = p_action.GetUnknown28();
			if (!sender) {
				sender = p_controller->FUN_100c1e70(p_action);
			}

			if (sender) {
				p_action.SetOrigin(sender);
				object->SetCompositePresenter((MxCompositePresenter*) sender);
			}
			else {
				if (!p_action.GetOrigin()) {
					p_action.SetOrigin(this);
				}
				object->SetCompositePresenter(NULL);
			}

			if (object->StartAction(p_controller, &p_action) == SUCCESS) {
				if (sender) {
					NotificationManager()->Send(sender, MxType4NotificationParam(this, &p_action, object));
				}

				if (p_action.GetUnknown84()) {
					NotificationManager()->Send(
						p_action.GetUnknown84(),
						MxStartActionNotificationParam(c_notificationStartAction, object, &p_action, FALSE)
					);
				}
				result = SUCCESS;
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100b0680
MxOmni* MxOmni::GetInstance()
{
	return g_instance;
}

// FUNCTION: LEGO1 0x100b0690
void MxOmni::DestroyInstance()
{
	if (g_instance != NULL) {
		delete g_instance;
		g_instance = NULL;
	}
}

// FUNCTION: LEGO1 0x100b06b0
MxBool MxOmni::ActionSourceEquals(MxDSAction* p_action, const char* p_name)
{
	if (!strcmp(p_action->GetSourceName(), p_name)) {
		return TRUE;
	}

	if (p_action->IsA("MxDSMultiAction")) {
		MxDSActionListCursor cursor(((MxDSMultiAction*) p_action)->GetActionList());
		MxDSAction* action;

		while (cursor.Next(action)) {
			if (ActionSourceEquals(action, p_name)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100b07f0
MxLong MxOmni::Notify(MxParam& p_param)
{
	AUTOLOCK(m_criticalSection);

	if (((MxNotificationParam&) p_param).GetNotification() != c_notificationEndAction) {
		return 0;
	}

	return HandleEndAction(p_param);
}

// FUNCTION: LEGO1 0x100b0880
MxLong MxOmni::HandleEndAction(MxParam& p_param)
{
	MxDSAction* action = ((MxEndActionNotificationParam&) p_param).GetAction();
	MxStreamController* controller = Streamer()->GetOpenStream(action->GetAtomId().GetInternal());

	if (controller != NULL) {
		action = (MxDSAction*) controller->GetUnk0x54().Find(action);
		if (action) {
			if (ActionSourceEquals(action, "LegoLoopingAnimPresenter") == FALSE) {
				delete controller->GetUnk0x54().FindAndErase(action);
			}
		}
	}

	if (((MxEndActionNotificationParam&) p_param).GetSender()) {
		delete ((MxEndActionNotificationParam&) p_param).GetSender();
	}

	if (((MxEndActionNotificationParam&) p_param).GetAction()) {
		delete ((MxEndActionNotificationParam&) p_param).GetAction();
	}

	return 1;
}

// FUNCTION: LEGO1 0x100b0900
const char* MxOmni::GetHD()
{
	return g_hdPath;
}

// FUNCTION: LEGO1 0x100b0910
void MxOmni::SetHD(const char* p_hd)
{
	strcpy(g_hdPath, p_hd);
}

// FUNCTION: LEGO1 0x100b0940
const char* MxOmni::GetCD()
{
	return g_cdPath;
}

// FUNCTION: LEGO1 0x100b0950
void MxOmni::SetCD(const char* p_cd)
{
	strcpy(g_cdPath, p_cd);
}

// FUNCTION: LEGO1 0x100b0980
MxBool MxOmni::IsSound3D()
{
	return g_use3dSound;
}

// FUNCTION: LEGO1 0x100b0990
void MxOmni::SetSound3D(MxBool p_use3dSound)
{
	g_use3dSound = p_use3dSound;
}

// FUNCTION: LEGO1 0x100b09a0
MxBool MxOmni::DoesEntityExist(MxDSAction& p_dsAction)
{
	if (m_streamer->FUN_100b9b30(p_dsAction)) {
		MxNotificationPtrList* notifications = m_notificationManager->GetQueue();

		if (!notifications || notifications->size() == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

// FUNCTION: LEGO1 0x100b09d0
void MxOmni::Pause()
{
	if (m_paused == FALSE && m_timer != NULL && m_soundManager != NULL) {
		m_timer->Start();
		m_soundManager->Pause();
		m_paused = TRUE;
	}
}

// FUNCTION: LEGO1 0x100b0a00
void MxOmni::Resume()
{
	if (m_paused != FALSE && m_timer != NULL && m_soundManager != NULL) {
		m_timer->Stop();
		m_soundManager->Resume();
		m_paused = FALSE;
	}
}
