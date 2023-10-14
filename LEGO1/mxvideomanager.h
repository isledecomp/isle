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
  virtual ~MxVideoManager() override;

  virtual MxResult Tickle() override; // vtable+0x8
  virtual void Destroy() override; // vtable+0x18
  virtual MxResult vtable0x28(
    MxVideoParam& p_videoParam,
    LPDIRECTDRAW p_pDirectDraw,
    LPDIRECTDRAWSURFACE p_pDDSurface,
    LPDIRECTDRAWSURFACE p_ddSurface1,
    LPDIRECTDRAWSURFACE p_ddSurface2,
    LPDIRECTDRAWCLIPPER p_ddClipper,
    MxU32 p_frequencyMS,
    MxBool p_createThread
  ); // vtable+0x28
  virtual MxResult vtable0x2c(MxVideoParam& p_videoParam, undefined4 p_unknown1, MxU8 p_unknown2); // vtable+0x2c

  __declspec(dllexport) void InvalidateRect(MxRect32 &);
  __declspec(dllexport) virtual MxLong RealizePalette(MxPalette *); // vtable+0x30

  MxVideoManager();

  MxResult Init();
  void Destroy(MxBool p_fromDestructor);
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
