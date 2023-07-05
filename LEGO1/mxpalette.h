#ifndef MXPALETTE_H
#define MXPALETTE_H

#include <ddraw.h>

#include "mxcore.h"
#include "mxtypes.h"

// VTABLE 0x100dc848
// SIZE 0x414
class MxPalette : public MxCore
{
public:
  __declspec(dllexport) MxBool operator==(MxPalette &);
  __declspec(dllexport) void Detach();

  MxPalette();
  MxPalette(const RGBQUAD *);
  virtual ~MxPalette();

  void ApplySystemEntriesToPalette(LPPALETTEENTRY p_entries);
  MxPalette* Clone();
  void GetDefaultPalette(LPPALETTEENTRY p_entries);
  MxResult GetEntries(LPPALETTEENTRY p_entries);
  MxResult SetEntries(LPPALETTEENTRY p_palette);
  MxResult SetSkyColor(LPPALETTEENTRY p_sky_color);
  void Reset(MxBool p_ignoreSkyColor);
private:
  LPDIRECTDRAWPALETTE m_palette;
  PALETTEENTRY m_entries[256];
  MxBool m_overrideSkyColor;
  PALETTEENTRY m_skyColor;
};

#endif // MXPALETTE_H
