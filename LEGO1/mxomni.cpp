#include "mxomni.h"

#include "mxatomidcounter.h"
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
#include "mxautolocker.h"

// 0x101015b8
char g_hdPath[1024];

// 0x101019b8
char g_cdPath[1024];

// 0x10101db8
MxBool g_use3dSound;

// 0x101015b0
MxOmni *MxOmni::g_instance = NULL;

// OFFSET: LEGO1 0x100aef10
MxOmni::MxOmni()
{
  Init();
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

// OFFSET: LEGO1 0x100b0090
MxResult MxOmni::Start(MxDSAction* p_dsAction)
{
  MxResult result = FAILURE;
  if(p_dsAction->GetAtomId().GetInternal() != NULL && p_dsAction->GetObjectId() != -1 && m_streamer != NULL)
  {
    result = m_streamer->Unknown100b99b0(p_dsAction);
  }

  return result;
}

// OFFSET: LEGO1 0x100b00c0 STUB
void MxOmni::DeleteObject(MxDSAction &ds)
{
  // TODO
}

// OFFSET: LEGO1 0x100b09a0 STUB
MxBool MxOmni::DoesEntityExist(MxDSAction &ds)
{
  // TODO
  return FALSE;
}

// OFFSET: LEGO1 0x100b00e0 STUB
void MxOmni::vtable0x2c()
{
  // TODO
}

// OFFSET: LEGO1 0x100aefb0 STUB
int MxOmni::vtable0x30(char*, int, MxCore*)
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x100aefc0
void MxOmni::NotifyCurrentEntity(MxParam *p_param)
{
}

// OFFSET: LEGO1 0x100b09d0
void MxOmni::StartTimer()
{
  if (m_timerRunning == FALSE && m_timer != NULL && m_soundManager != NULL)
  {
    m_timer->Start();
    m_soundManager->vtable0x34();
    m_timerRunning = TRUE;
  }
}

// OFFSET: LEGO1 0x100b0a00
void MxOmni::StopTimer()
{
  if (m_timerRunning != FALSE && m_timer != NULL && m_soundManager != NULL)
  {
    m_timer->Stop();
    m_soundManager->vtable0x38();
    m_timerRunning = FALSE;
  }
}

// OFFSET: LEGO1 0x10058a90
MxBool MxOmni::IsTimerRunning()
{
  return m_timerRunning;
}

// OFFSET: LEGO1 0x100b0690
void MxOmni::DestroyInstance()
{
  if (g_instance != NULL)
  {
    delete g_instance;
    g_instance = NULL;
  }
}

// OFFSET: LEGO1 0x100b0900
const char *MxOmni::GetHD()
{
  return g_hdPath;
}

// OFFSET: LEGO1 0x100b0940
const char *MxOmni::GetCD()
{
  return g_cdPath;
}

// OFFSET: LEGO1 0x100b0980
MxBool MxOmni::IsSound3D()
{
  return g_use3dSound;
}

// OFFSET: LEGO1 0x100b0910
void MxOmni::SetHD(const char *p_hd)
{
  strcpy(g_hdPath, p_hd);
}

// OFFSET: LEGO1 0x100b0950
void MxOmni::SetCD(const char *p_cd)
{
  strcpy(g_cdPath, p_cd);
}

// OFFSET: LEGO1 0x100b0990
void MxOmni::SetSound3D(MxBool p_3dsound)
{
  g_use3dSound = p_3dsound;
}


// OFFSET: LEGO1 0x100b0680
MxOmni *MxOmni::GetInstance()
{
  return g_instance;
}

// OFFSET: LEGO1 0x100af0b0
void MxOmni::SetInstance(MxOmni *instance)
{
  g_instance = instance;
}

// OFFSET: LEGO1 0x100af0c0
MxResult MxOmni::Create(MxOmniCreateParam &p)
{
  MxResult result = FAILURE;
  m_atomIdCounterSet = new MxAtomIdCounterSet();
  if (m_atomIdCounterSet == NULL)
  {
    goto failure;
  }
  m_mediaPath = p.GetMediaPath();
  m_windowHandle = p.GetWindowHandle();
  if (p.CreateFlags().CreateObjectFactory())
  {
    MxObjectFactory *objectFactory = new MxObjectFactory();
    this->m_objectFactory = objectFactory;

    if (objectFactory == NULL)
      goto failure;
  }

  if (p.CreateFlags().CreateVariableTable())
  {
    MxVariableTable *variableTable = new MxVariableTable();
    this->m_variableTable = variableTable;

    if (variableTable == NULL)
      goto failure;
  }

  if (p.CreateFlags().CreateTimer())
  {
    MxTimer *timer = new MxTimer();
    this->m_timer = timer;

    if (timer == NULL)
      return FAILURE;
  }

  if (p.CreateFlags().CreateTickleManager())
  {
    this->m_tickleManager = new MxTickleManager();

    if (m_tickleManager == NULL)
      goto failure;
  }

  if (p.CreateFlags().CreateNotificationManager())
  {
    MxNotificationManager *notificationManager = new MxNotificationManager();
    this->m_notificationManager = notificationManager;

    if (notificationManager == NULL || notificationManager->Create(100, 0) != SUCCESS)
      goto failure;
  }

  if (p.CreateFlags().CreateStreamer())
  {
    MxStreamer *streamer = new MxStreamer();
    this->m_streamer = streamer;

    if (streamer == NULL || streamer->Init() != SUCCESS)
      goto failure;
  }

  if (p.CreateFlags().CreateVideoManager())
  {
    MxVideoManager *videoManager = new MxVideoManager();
    this->m_videoManager = videoManager;

    if (videoManager != NULL && videoManager->vtable0x2c(p.GetVideoParam(), 100, 0) != SUCCESS)
    {
      delete m_videoManager;
      m_videoManager = NULL;
    }
  }

  if (p.CreateFlags().CreateSoundManager())
  {
    MxSoundManager *soundManager = new MxSoundManager();
    this->m_soundManager = soundManager;

    //TODO
    if (soundManager != NULL && soundManager->StartDirectSound(10, 0) != SUCCESS)
    {
      delete m_soundManager;
      m_soundManager = NULL;
    }
  }

  if (p.CreateFlags().CreateMusicManager())
  {
    MxMusicManager *musicManager = new MxMusicManager();
    this->m_musicManager = musicManager;
    if (musicManager != NULL && musicManager->StartMIDIThread(50, 0) != SUCCESS)
    {
      delete m_musicManager;
      m_musicManager = NULL;
    }
  }

  if (p.CreateFlags().CreateEventManager())
  {
    MxEventManager *eventManager = new MxEventManager();
    this->m_eventManager = eventManager;
    if (m_eventManager != NULL && m_eventManager->CreateEventThread(50, 0) != SUCCESS)
    {
      delete m_eventManager;
      m_eventManager = NULL;
    }
  }

  result = SUCCESS;
  failure:
  if (result != SUCCESS)
  {
    Destroy();
  }

  return result;
}

// OFFSET: LEGO1 0x100afe90
void MxOmni::Destroy()
{
  // FIXME: Stub

  /*
  // TODO: private members
  if (m_notificationManager) {
    while (m_notificationManager->m_queue->size()) {
      m_notificationManager->Tickle();
    }
  }

  m_notificationManager->m_active = 0;
  */

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
      MxAtomIdCounter *value = *begin;
      m_atomIdCounterSet->erase(begin);
      delete value;
    }
    delete m_atomIdCounterSet;
  }
}

// OFFSET: LEGO1 0x100b07f0
MxLong MxOmni::Notify(MxParam &p)
{
  MxAutoLocker lock(&this->m_criticalsection);

  if (((MxNotificationParam&) p).GetType() != MXSTREAMER_UNKNOWN)
    return 0;

  return HandleNotificationType2(p);
}

// OFFSET: LEGO1 0x100b0880 STUB
MxResult MxOmni::HandleNotificationType2(MxParam& p_param)
{
  // TODO STUB
  return FAILURE;
}

// OFFSET: LEGO1 0x100acea0
MxObjectFactory *ObjectFactory()
{
  return MxOmni::GetInstance()->GetObjectFactory();
}

// OFFSET: LEGO1 0x100aceb0
MxNotificationManager *NotificationManager()
{
  return MxOmni::GetInstance()->GetNotificationManager();
}

// OFFSET: LEGO1 0x100acec0
MxTickleManager *TickleManager()
{
  return MxOmni::GetInstance()->GetTickleManager();
}

// OFFSET: LEGO1 0x100aced0
MxTimer *Timer()
{
  return MxOmni::GetInstance()->GetTimer();
}

// OFFSET: LEGO1 0x100acee0
MxAtomIdCounterSet *AtomIdCounterSet()
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
