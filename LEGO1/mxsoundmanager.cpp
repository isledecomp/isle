#include "mxsoundmanager.h"
#include "mxticklemanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(MxSoundManager, 0x3c);

// OFFSET: LEGO1 0x100ae740
MxSoundManager::MxSoundManager()
{
  Init();
}

// OFFSET: LEGO1 0x100ae7d0
MxSoundManager::~MxSoundManager()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100ae830
void MxSoundManager::Init()
{
  m_unk30 = 0;
  m_dsBuffer = NULL;
}

// OFFSET: LEGO1 0x100ae840
void MxSoundManager::Destroy(MxBool p_param)
{
  if (this->m_thread) {
    this->m_thread->Terminate();
    delete this->m_thread;
  }
  else {
    TickleManager()->UnregisterClient(this);
  }

  this->m_criticalSection.Enter();

  if (this->m_dsBuffer) {
    this->m_dsBuffer->Release();
  }

  Init();
  this->m_criticalSection.Leave();

  if (!p_param) {
    MxAudioManager::Destroy();
  }
}