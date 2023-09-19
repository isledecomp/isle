#include "mxaudiomanager.h"

DECOMP_SIZE_ASSERT(MxAudioManager, 0x30);

// GLOBAL: LEGO1 0x10102108
MxS32 MxAudioManager::g_unkCount = 0;

// OFFSET: LEGO1 0x100b8d00
MxAudioManager::MxAudioManager()
{
  Init();
}

// OFFSET: LEGO1 0x100b8d90
MxAudioManager::~MxAudioManager()
{
  LockedReinitialize(TRUE);
}

// OFFSET: LEGO1 0x100b8df0
void MxAudioManager::Init()
{
  this->m_unk2c = 100;
}

// OFFSET: LEGO1 0x100b8e00
void MxAudioManager::LockedReinitialize(MxBool p_skipDestroy)
{
  this->m_criticalSection.Enter();
  g_unkCount--;
  Init();
  this->m_criticalSection.Leave();

  if (!p_skipDestroy)
    MxMediaManager::Destroy();
}

// OFFSET: LEGO1 0x100b8e40
MxResult MxAudioManager::InitPresenters()
{
  MxResult result = FAILURE;
  MxBool success = FALSE;

  if (MxMediaManager::InitPresenters() == SUCCESS) {
    this->m_criticalSection.Enter();
    success = TRUE;
    result = SUCCESS;
    g_unkCount++;
  }

  if (result)
    Destroy();

  if (success)
    this->m_criticalSection.Leave();

  return result;
}

// OFFSET: LEGO1 0x100b8e90
void MxAudioManager::Destroy()
{
  LockedReinitialize(FALSE);
}