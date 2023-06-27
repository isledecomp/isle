#ifndef LEGOSTATE_H
#define LEGOSTATE_H

#include "mxcore.h"

#ifndef undefined4
#define undefined4 int
#endif

class LegoState : public MxCore
{
public:
  // OFFSET: LEGO1 0x100060d0
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    return "LegoState";
  }; 

  // OFFSET: LEGO1 0x100060e0
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, LegoState::GetClassName()) || MxCore::IsClass(name);
  };

  virtual MxBool VTable0x14(); // vtable+0x14
  virtual MxBool VTable0x18(); // vtable+0x18
  virtual undefined4 VTable0x1c(undefined4 param); // vtable+0x1c
};

#endif // LEGOSTATE_H
