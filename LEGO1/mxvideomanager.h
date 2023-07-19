#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

#include "mxunknown100dc6b0.h"
#include "mxdisplaysurface.h"
#include "mxvideoparam.h"

// VTABLE 0x100dc810
// SIZE 0x64
class MxVideoManager : public MxUnknown100dc6b0
{
public:
  virtual ~MxVideoManager();

  virtual MxLong Tickle(); // vtable+0x8

  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual MxLong RealizePalette(MxPalette *); // vtable+0x30

  MxVideoManager();

  int Init();

  inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }
  inline LPDIRECTDRAW GetDirectDraw() { return this->m_pDirectDraw; }
private:
  MxVideoParam m_videoParam;
  LPDIRECTDRAW m_pDirectDraw;
  LPDIRECTDRAWSURFACE m_unk54;
  MxDisplaySurface *m_displaySurface;
  int m_unk5c;
  MxBool m_unk60;
};

#endif // MXVIDEOMANAGER_H
