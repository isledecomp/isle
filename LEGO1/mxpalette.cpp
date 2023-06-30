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
  if ((rasterCaps & RC_PALETTE) != 0) {
    int paletteSize = GetDeviceCaps(hdc, SIZEPALETTE);
    if (paletteSize == 256) {
      GetSystemPaletteEntries(hdc, 0, 256, p_entries);
      p_entries += 10;
      memcpy(p_entries, this->m_entries, sizeof(this->m_entries));
    }
  }
  
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
  