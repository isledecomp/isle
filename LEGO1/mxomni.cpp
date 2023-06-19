#include "mxomni.h"

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
