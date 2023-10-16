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
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c0450
void MxEventManager::Init()
{
  // This is intentionally left blank
}

// OFFSET: LEGO1 0x100c0460
void MxEventManager::Destroy(MxBool p_fromDestructor)
{
  if (m_thread != NULL) {
    m_thread->Terminate();
    delete m_thread;
  }
  else
    TickleManager()->UnregisterClient(this);

  if (!p_fromDestructor)
    MxMediaManager::Destroy();
}

// OFFSET: LEGO1 0x100c04a0
MxResult MxEventManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
  MxResult status = FAILURE;
  MxBool locked = FALSE;

  MxResult result = MxMediaManager::InitPresenters();
  if (result == SUCCESS) {
    if (p_createThread) {
      this->m_criticalSection.Enter();
      locked = TRUE;
      this->m_thread = new MxTickleThread(this, p_frequencyMS);

      if (!this->m_thread || this->m_thread->Start(0, 0) != SUCCESS)
        goto done;
    }
    else
      TickleManager()->RegisterClient(this, p_frequencyMS);

    status = SUCCESS;
  }

done:
  if (status != SUCCESS)
    Destroy();

  if (locked)
    this->m_criticalSection.Leave();

  return status;
}

// OFFSET: LEGO1 0x100c0590
void MxEventManager::Destroy()
{
  Destroy(FALSE);
}
