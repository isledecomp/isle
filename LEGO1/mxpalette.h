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
  __declspec(dllexport) unsigned char operator==(MxPalette &);
  __declspec(dllexport) void Detach();

  MxResult GetEntries(LPPALETTEENTRY p_entries);

private:
  LPDIRECTDRAWPALETTE m_pDirectDrawPalette;
  PALETTEENTRY m_entries[256];
  // there's a bit more here
};

#endif // MXPALETTE_H
