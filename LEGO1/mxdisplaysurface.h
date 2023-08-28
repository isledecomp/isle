#ifndef MXDISPLAYSURFACE_H
#define MXDISPLAYSURFACE_H

#include <ddraw.h>

#include "mxcore.h"
#include "mxpalette.h"
#include "mxvideoparam.h"

#include "decomp.h"

// VTABLE 0x100dc768
// SIZE 0xac
class MxDisplaySurface : public MxCore
{
public:
  MxDisplaySurface();
  virtual ~MxDisplaySurface() override;

  void Reset();

  virtual MxResult Init(MxVideoParam &p_videoParam, LPDIRECTDRAWSURFACE p_ddSurface1, LPDIRECTDRAWSURFACE p_ddSurface2, LPDIRECTDRAWCLIPPER p_ddClipper);
  virtual MxResult Create(MxVideoParam &p_videoParam);
  virtual void Clear();
  virtual void SetPalette(MxPalette *p_palette);
  virtual void vtable24(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable2c(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual MxBool vtable30(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual undefined4 vtable34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual void Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual void GetDC(HDC *p_hdc);
  virtual void ReleaseDC(HDC p_hdc);
  virtual undefined4 vtable44(undefined4, undefined4*, undefined4, undefined4);

private:
  MxVideoParam m_videoParam;
  LPDIRECTDRAWSURFACE m_ddSurface1;
  LPDIRECTDRAWSURFACE m_ddSurface2;
  LPDIRECTDRAWCLIPPER m_ddClipper;
  MxBool m_initialized;
  DDSURFACEDESC m_surfaceDesc;
  MxU16 *m_16bitPal;
};

#endif // MXDISPLAYSURFACE_H
