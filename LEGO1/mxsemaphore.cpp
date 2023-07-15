
#include "mxsemaphore.h"

// OFFSET: LEGO1 0x100c87d0
MxSemaphore::MxSemaphore()
{
  m_hSemaphore = NULL;
}

// OFFSET: LEGO1 0x100c8800
MxResult MxSemaphore::Init(MxU32 p_initialCount, MxU32 p_maxCount)
{
  MxResult result = FAILURE;
  if (m_hSemaphore = CreateSemaphoreA(NULL, p_initialCount, p_maxCount, NULL))
    result = SUCCESS;
  return result;
}

// OFFSET: LEGO1 0x100c8830
void MxSemaphore::Wait(MxU32 p_timeoutMS)
{
  WaitForSingleObject(m_hSemaphore, p_timeoutMS);
}

// OFFSET: LEGO1 0x100c8850
void MxSemaphore::Release(MxU32 p_releaseCount)
{
  ReleaseSemaphore(m_hSemaphore, p_releaseCount, NULL);
}