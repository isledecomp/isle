#ifndef MXPALETTE_H
#define MXPALETTE_H

#include <ddraw.h>

#include "mxcore.h"
#include "mxresult.h"

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
