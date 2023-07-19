#ifndef MXDISPLAYSURFACE_H
#define MXDISPLAYSURFACE_H

#include <ddraw.h>

#include "mxcore.h"
#include "mxpalette.h"
#include "mxvideoparam.h"

#include "decomp.h"

// VTABLE 0x100dc768
class MxDisplaySurface : public MxCore
{
public:
  MxDisplaySurface();
  virtual ~MxDisplaySurface() override;

  virtual MxResult Init(MxVideoParam *p_videoParam, LPDIRECTDRAWSURFACE p_surface1, LPDIRECTDRAWSURFACE p_surface2, LPDIRECTDRAWCLIPPER p_clipper);
  virtual MxResult Create(MxVideoParam *p_videoParam);
  virtual void Clear();
  virtual void SetPalette(MxPalette *p_palette);
  virtual void vtable24(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable2c(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual MxBool vtable30(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual undefined4 vtable34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual void Display(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual undefined4 vtable3c(undefined4*);
  virtual undefined4 vtable40(undefined4);
  virtual undefined4 vtable44(undefined4, undefined4*, undefined4, undefined4);
};

#endif // MXDISPLAYSURFACE_H
