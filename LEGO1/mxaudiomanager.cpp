#include "mxaudiomanager.h"

// OFFSET: LEGO1 0x100b8d00
MxAudioManager::MxAudioManager()
{
  Init();
}

// OFFSET: LEGO1 0x100b8d90
MxAudioManager::~MxAudioManager()
{
  LockedReinitialize(1);
}

// OFFSET: LEGO1 0x100b8df0
void MxAudioManager::Init()
{
  this->m_unk2c = 100;
}

// OFFSET: LEGO1 0x100b8e00
void MxAudioManager::LockedReinitialize(MxS8 p_skipTeardown)
{
  this->m_criticalSection.Enter();
  Init();
  this->m_criticalSection.Leave();

  if (p_skipTeardown) {
    Teardown();
  }
}