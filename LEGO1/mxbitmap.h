#ifndef MXBITMAP_H
#define MXBITMAP_H

#include "mxpalette.h"

class MxBitmap
{
public:
  __declspec(dllexport) MxBitmap();
  __declspec(dllexport) virtual ~MxBitmap();
  __declspec(dllexport) virtual MxPalette *CreatePalette();
  __declspec(dllexport) virtual long Read(const char *);
};

#endif // MXBITMAP_H
