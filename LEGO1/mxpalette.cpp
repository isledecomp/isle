#include "mxpalette.h"

// OFFSET: LEGO1 0x100bee30
MxPalette::MxPalette()
{
  this->m_overrideSkyColor = FALSE;
  this->m_palette = NULL;
  GetDefaultPalette(this->m_entries);
  this->m_skyColor = this->m_entries[141];
}

// OFFSET: LEGO1 100bef90
MxPalette::~MxPalette()
{
  if (m_palette) {
    m_palette->Release();
  }
}

// OFFSET: LEGO1 0x100bf390
void MxPalette::ApplySystemEntriesToPalette(LPPALETTEENTRY p_entries)
{
  // FIXME: incomplete
  HDC hdc = GetDC(NULL);
  unsigned int rastercaps = GetDeviceCaps(hdc, RASTERCAPS);
  int sizepalettecaps;
  if ((rastercaps & RC_PALETTE) != 0) {
    sizepalettecaps = GetDeviceCaps(hdc, SIZEPALETTE);
    if(sizepalettecaps = 256) {
      GetSystemPaletteEntries(hdc,0,10,p_entries);
      GetSystemPaletteEntries(hdc,246,10,p_entries + 0xf6);
      ReleaseDC(NULL, hdc);
    }
  }
  // FIXME: we get g_defaultPalette here, we need to define that, then we cna do the memcpy's
}

// OFFSET: LEGO1 100bf0b0
MxPalette* MxPalette::Clone()
{
  // FIXME: doesnt match
  MxPalette *pal = (MxPalette *) malloc(0x414);
  if(pal != NULL) {
    GetEntries(pal->m_entries);
    pal->m_overrideSkyColor = m_overrideSkyColor;
  }
  return pal;
}

// OFFSET: LEGO1 0x100bf150
MxResult MxPalette::GetEntries(LPPALETTEENTRY p_entries)
{
  memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
  return SUCCESS;
}

// OFFSET: LEGO1 0x100bf420
void MxPalette::GetDefaultPalette(LPPALETTEENTRY p_entries)
{
  HDC hdc = GetDC((HWND) NULL);
  int rasterCaps = GetDeviceCaps(hdc, RASTERCAPS);
  LPPALETTEENTRY src;
  int count;
  
  if ((rasterCaps & RC_PALETTE) != 0 && GetDeviceCaps(hdc, SIZEPALETTE) == 256) {
    GetSystemPaletteEntries(hdc, 0, 256, p_entries);
    count = 256 - 2 * 10;
    src = (LPPALETTEENTRY) &m_palette[10];
    p_entries += 10;
  } else {
    src = (LPPALETTEENTRY) m_palette;
    count = 256;
  }
  void* dest;
  memcpy(dest, p_entries, count * sizeof(PALETTEENTRY));
  ReleaseDC((HWND) NULL, hdc);
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
  this->m_palette = NULL;
}
  