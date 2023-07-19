#include "mxvideomanager.h"

// OFFSET: LEGO1 0x100be2a0 STUB
MxVideoManager::~MxVideoManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100bea90 STUB
MxLong MxVideoManager::Tickle()
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
  this->m_pDirectDraw = NULL;
  this->m_unk54 = NULL;
  this->m_displaySurface = NULL;
  this->m_unk5c = 0;
  this->m_videoParam.SetPalette(NULL);
  this->m_unk60 = FALSE;
  return 0;
}

// OFFSET: LEGO1 0x100bea60 STUB
void MxVideoManager::InvalidateRect(MxRect32 &p_rect)
{
  // TODO
}

// OFFSET: LEGO1 0x100bebe0
MxLong MxVideoManager::RealizePalette(MxPalette *p_palette)
{
  PALETTEENTRY paletteEntries[256];

  this->m_criticalSection.Enter();

  if (p_palette && this->m_videoParam.GetPalette()) {
    p_palette->GetEntries(paletteEntries);
    this->m_videoParam.GetPalette()->SetEntries(paletteEntries);
    this->m_displaySurface->SetPalette(this->m_videoParam.GetPalette());
  }

  this->m_criticalSection.Leave();
  return 0;
}
