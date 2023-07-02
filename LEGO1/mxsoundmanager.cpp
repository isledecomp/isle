#include "mxsoundmanager.h"

// OFFSET: LEGO1 0x100ae740
MxSoundManager::MxSoundManager()
{
  Init();
}

// OFFSET: LEGO1 0x100ae7d0 STUB
MxSoundManager::~MxSoundManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100ae830
void MxSoundManager::Init()
{
  m_unk30 = 0;
  m_unk34 = 0;
}

