#ifndef BUMPBOUY_H
#define BUMPBOUY_H

#include "legoanimactor.h"
#include "mxtypes.h"

// VTABLE 0x100d6790
class BumpBouy : public LegoAnimActor
{
public:
  // OFFSET: LEGO1 0x100274e0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0394
    return "BumpBouy";
  }

  // OFFSET: LEGO1 0x10027500
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, BumpBouy::ClassName()) || LegoAnimActor::IsA(name);
  }
};

#endif // BUMPBOUY_H
