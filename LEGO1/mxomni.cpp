#include "mxomni.h"

MxOmni *MxOmni::m_instance = NULL;

MxOmni *MxOmni::GetInstance()
{
  return m_instance;
}

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

MxTimer* Timer()
{
  return MxOmni::GetInstance()->GetTimer();
}