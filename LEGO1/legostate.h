#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "mxcore.h"

// VTABLE 0x100d46c0
class LegoState : public MxCore
{
public:
  virtual ~LegoState() override; // vtable+0x00

  // OFFSET: LEGO1 0x100060d0
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f01b8
    return "LegoState";
  }

  // OFFSET: LEGO1 0x100060e0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoState::ClassName()) || MxCore::IsA(name);
  }

};

#endif // LEGOSTATE_H
