#include "mxomni.h"

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
  m_unk64 = NULL;
}

// OFFSET: LEGO1 0x100b0090 STUB
void MxOmni::vtable0x20()
{
  // TODO
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

// OFFSET: LEGO1 0x100aefc0 STUB
void MxOmni::NotifyCurrentEntity()
{
  // TODO
}

// OFFSET: LEGO1 0x100b09d0 STUB
void MxOmni::StartTimer()
{
  // TODO
}

// OFFSET: LEGO1 0x100b0a00 STUB
void MxOmni::vtable0x3c()
{
  // TODO
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
  m_atomIdCounterSet = new MxAtomIdCounterSet();

  if (p.CreateFlags().CreateVariableTable())
  {
    MxVariableTable *variableTable = new MxVariableTable();
    this->m_variableTable = variableTable;

    if (variableTable == NULL)
      return FAILURE;
  }

  if (p.CreateFlags().CreateTimer())
  {
    MxTimer *timer = new MxTimer();
    this->m_timer = timer;

    if (timer == NULL)
      return FAILURE;
  }

  return SUCCESS;
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
  // FIXME: Stub
  return 0;
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
