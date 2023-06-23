#include "mxpalette.h"

// OFFSET: LEGO1 0x100bf150
int MxPalette::GetEntries(LPPALETTEENTRY p_entries)
{
  memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
  return 0;
}