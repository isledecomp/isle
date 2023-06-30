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
  virtual ~MxPalette();

  MxPalette* Clone();
  void GetDefaultPalette(LPPALETTEENTRY p_entries);
  MxResult GetEntries(LPPALETTEENTRY p_entries);

private:
  LPDIRECTDRAWPALETTE m_palette;
  PALETTEENTRY m_entries[256];
  MxBool m_overrideSkyColor;
  PALETTEENTRY m_skyColor;
};

#endif // MXPALETTE_H
