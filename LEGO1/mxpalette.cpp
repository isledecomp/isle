#include "mxpalette.h"

// OFFSET: LEGO1 0x100bee30
MxPalette::MxPalette()
{
  this->m_overrideSkyColor = FALSE;
  this->m_attached = NULL;
  // GetDefaultSkyPalette
  // this->m_skyColor = whatever it is once i figure out how m_palette works
}

// OFFSET: LEGO1 0x100bf150
MxResult MxPalette::GetEntries(LPPALETTEENTRY p_entries)
{
  memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
  return SUCCESS;
}

// OFFSET: LEGO1 0x100bf330
void MxPalette::Detach()
{
  this->m_attached = NULL;
}