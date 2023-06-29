#include "mxomni.h"

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
  m_unk44 = NULL;
  m_unk64 = NULL;
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
}

// OFFSET: LEGO1 0x100b07f0
long MxOmni::Notify(MxParam &p)
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