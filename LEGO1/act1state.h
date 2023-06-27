#ifndef ACT1STATE_H
#define ACT1STATE_H

#include "legostate.h"

#ifndef undefined4
#define undefined4 int
#endif

class Act1State : public LegoState
{
public:
  Act1State();

  // OFFSET: LEGO1 0x100338a0
  inline virtual const char *GetClassName() const // vtable+0x0c
  {
    return "Act1State";
  };

  // OFFSET: LEGO1 0x100338b0
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, Act1State::GetClassName()) || LegoState::IsClass(name);
  };

  virtual MxBool VTable0x18();
  virtual undefined4 VTable0x1c(undefined4 param);
};

#endif // ACT1STATE_H
