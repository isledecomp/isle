#include "mxbackgroundaudiomanager.h"

DECOMP_SIZE_ASSERT(MxBackgroundAudioManager, 0x150)

// OFFSET: LEGO1 0x1007ea90
MxBackgroundAudioManager::MxBackgroundAudioManager()
{
  NotificationManager()->Register(this);
  m_unka0 = 0;
  m_unk138 = 0;
  m_unk13c = 0;
  m_unk140 = 0;
  m_unk144 = 0;
  m_unk148 = 0;
  m_musicEnabled = FALSE;
}

// OFFSET: LEGO1 0x1007ec20
MxBackgroundAudioManager::~MxBackgroundAudioManager()
{
  // TODO
  NotificationManager()->Unregister(this);
}

// OFFSET: LEGO1 0x1007f470
void MxBackgroundAudioManager::Stop()
{
  // TODO
}

// OFFSET: LEGO1 0x1007f5f0
void MxBackgroundAudioManager::Enable(MxBool p)
{
 if ((this->m_musicEnabled != p) && (this->m_musicEnabled = p, !p)) {
   Stop();
 }
}

// OFFSET: LEGO1 0x1007f650
void MxBackgroundAudioManager::Init()
{
  this->m_unka0 = 0;
  this->m_unk13c = 0;
}
