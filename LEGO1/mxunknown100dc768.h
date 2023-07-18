#ifndef MXUNKNOWN100DC768_H
#define MXUNKNOWN100DC768_H

#include "mxcore.h"
#include "mxpalette.h"

#include "decomp.h"

// VTABLE 0x100dc768
class MxUnknown100dc768 : public MxCore
{
public:
  MxUnknown100dc768();
  virtual ~MxUnknown100dc768() override;

  virtual undefined4 vtable14(undefined4, undefined4, undefined4, undefined4);
  virtual undefined4 vtable18(undefined4);
  virtual MxResult Reset();
  virtual void vtable20(MxPalette *p_palette);
  virtual void vtable24(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable28(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual MxBool vtable2c(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual MxBool vtable30(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, undefined4, MxBool);
  virtual undefined4 vtable34(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual void vtable38(undefined4, undefined4, undefined4, undefined4, undefined4, undefined4);
  virtual undefined4 vtable3c(undefined4*);
  virtual undefined4 vtable40(undefined4);
  virtual undefined4 vtable44(undefined4, undefined4*, undefined4, undefined4);
};

#endif // MXUNKNOWN100DC768_H
