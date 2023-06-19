#include "mxomni.h"

// 0x101015b0
MxOmni* MxOmni::m_instance = NULL;

// OFFSET: LEGO1 0x100b0680
MxOmni *MxOmni::GetInstance()
{
  return m_instance;
}

// OFFSET: LEGO1 0x100af0c0
MxResult MxOmni::Create(const MxOmniCreateParam &p)
{
  if (p.CreateFlags().CreateTimer())
  {
    MxTimer *timer = new MxTimer();
    this->m_Timer = timer;

    if (timer == NULL)
      return FAILURE;
  }

  return SUCCESS;
}
