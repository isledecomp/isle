#ifndef MXVIDEOMANAGER_H
#define MXVIDEOMANAGER_H

#include "mxdisplaysurface.h"
#include "mxregion.h"
#include "mxmediamanager.h"
#include "mxvideoparam.h"

// VTABLE 0x100dc810
// SIZE 0x64
class MxVideoManager : public MxMediaManager
{
public:
  virtual ~MxVideoManager();

  virtual MxResult Tickle() override; // vtable+0x8
  virtual void vtable0x28(); // vtable+0x28 (TODO ARGUMENTS)
  virtual MxResult vtable0x2c(MxVideoParam& p_videoParam, undefined4 p_unknown1, MxU8 p_unknown2); // vtable+0x2c

  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual MxLong RealizePalette(MxPalette *); // vtable+0x30

  MxVideoManager();

  MxResult Init();
  void SortPresenterList();
  void UpdateRegion();

  inline MxVideoParam& GetVideoParam() { return this->m_videoParam; }
  inline LPDIRECTDRAW GetDirectDraw() { return this->m_pDirectDraw; }
  inline MxDisplaySurface *GetDisplaySurface() { return this->m_displaySurface; }
protected:
  MxVideoParam m_videoParam;
  LPDIRECTDRAW m_pDirectDraw;
  LPDIRECTDRAWSURFACE m_pDDSurface;
  MxDisplaySurface *m_displaySurface;
  MxRegion *m_region;
  MxBool m_unk60;
};

#endif // MXVIDEOMANAGER_H
