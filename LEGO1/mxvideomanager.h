#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

#include "mxcore.h"

class MxVideoManager : public MxCore
{
public:
  virtual ~MxVideoManager();

  virtual long Tickle(); // vtable+0x8

  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual long RealizePalette(MxPalette *); // vtable+0x30
};

#endif // MXVIDEOMANAGER_H
