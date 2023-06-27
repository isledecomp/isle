#include "mxvideomanager.h"

// OFFSET: LEGO1 0x100be2a0 STUB
MxVideoManager::~MxVideoManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100bea90 STUB
long MxVideoManager::Tickle()
{
  // TODO
  
  return 0;
}

// OFFSET: LEGO1 0x100be1f0
MxVideoManager::MxVideoManager()
{
  Init();
}

// OFFSET: LEGO1 0x100be320
int MxVideoManager::Init()
{
  this->m_unk50 = 0;
  this->m_unk54 = NULL;
  this->m_unk58 = NULL;
  this->m_unk5c = 0;
  this->m_videoParam.SetPalette(NULL);
  this->m_unk60 = MX_FALSE;
  return 0;
}

// OFFSET: LEGO1 0x100bebe0
long MxVideoManager::RealizePalette(MxPalette *p_palette)
{
  PALETTEENTRY paletteEntries[256];

  this->m_criticalSection.Enter();

  if (p_palette && this->m_videoParam.GetPalette())
  {
    p_palette->GetEntries(paletteEntries);
    // TODO
  }

  this->m_criticalSection.Leave();
  return 0;
}