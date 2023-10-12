#include "mxeventmanager.h"
#include "mxcriticalsection.h"
#include "mxthread.h"
#include "mxticklemanager.h"
#include "mxomni.h"

// OFFSET: LEGO1 0x100c0360
MxEventManager::MxEventManager()
{
  Init();
}

// OFFSET: LEGO1 0x100c03f0
MxEventManager::~MxEventManager()
{
  TerminateThread(TRUE);
}

// OFFSET: LEGO1 0x100c0450
void MxEventManager::Init()
{
  // This is intentionally left blank
}

// OFFSET: LEGO1 0x100c04a0
MxResult MxEventManager::CreateEventThread(MxU32 p_frequencyMS, MxBool p_noRegister)
{
  MxResult status = FAILURE;
  MxBool locked = FALSE;

  MxResult result = MxMediaManager::InitPresenters();
  if (result == SUCCESS)
  {
    if (p_noRegister)
    {
      this->m_criticalSection.Enter();
      locked = TRUE;
      this->m_thread = new MxTickleThread(this, p_frequencyMS);

      if (this->m_thread)
      {
        if (this->m_thread->Start(0, 0) == SUCCESS)
        {
          status = SUCCESS;
        }
      }
    }
    else
    {
      TickleManager()->RegisterClient(this, p_frequencyMS);
      status = SUCCESS;
    }
  }

  if (status != SUCCESS)
  {
    Destroy();
  }

  if (locked)
  {
    this->m_criticalSection.Leave();
  }

  return status;
}
