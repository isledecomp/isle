#include "mxpalette.h"

// OFFSET: LEGO1 0x100bf150
MxResult MxPalette::GetEntries(LPPALETTEENTRY p_entries)
{
  memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
  return SUCCESS;
}

// OFFSET: LEGO1 0x100bf340
MxBool MxPalette::operator==(MxPalette &)
{
  // TODO
  return FALSE;
}

// OFFSET: LEGO1 0x100bf330
void MxPalette::Detach()
{
  // TODO
}
