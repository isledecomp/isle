#include "mxaudiomanager.h"

DECOMP_SIZE_ASSERT(MxAudioManager, 0x30);

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
void MxAudioManager::LockedReinitialize(MxBool p_doTeardown)
{
  this->m_criticalSection.Enter();
  Init();
  this->m_criticalSection.Leave();

  if (p_doTeardown) {
    Teardown();
  }
}

// OFFSET: LEGO1 0x100b8e90
void MxAudioManager::Reinitialize()
{
  LockedReinitialize(FALSE);
}