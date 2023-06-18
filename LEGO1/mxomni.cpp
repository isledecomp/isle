#include "mxomni.h"

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
