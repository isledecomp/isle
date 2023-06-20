#include "mxomni.h"

// 0x101015b0
MxOmni* MxOmni::m_instance = NULL;

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

// OFFSET: LEGO1 0x100b0680
MxOmni *MxOmni::GetInstance()
{
  return m_instance;
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

// OFFSET: LEGO1 0x100aced0
MxTimer *Timer()
{
  return MxOmni::GetInstance()->GetTimer();
}
