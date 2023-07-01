#ifndef MXBITMAP_H
#define MXBITMAP_H

#include <stdlib.h>

#include "mxcore.h"
#include "mxpalette.h"
#include "mxtypes.h"

class MxBitmap : public MxCore
{
public:
  __declspec(dllexport) MxBitmap();
  __declspec(dllexport) virtual ~MxBitmap();
  __declspec(dllexport) virtual MxPalette *CreatePalette();
  __declspec(dllexport) virtual long Read(const char *);
private:
  BITMAPINFO *m_info;
  BITMAPINFOHEADER *m_bmiHeader;
  RGBQUAD *m_paletteData;
  LPVOID *m_data;
  MxBool m_unk18;
  MxPalette *m_palette;
};

#endif // MXBITMAP_H
