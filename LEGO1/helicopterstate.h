#ifndef HELICOPTERSTATE_H
#define HELICOPTERSTATE_H

#include "legostate.h"

// VTABLE 0x100d5418
// SIZE 0xc
class HelicopterState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000e0d0
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0144
    return "HelicopterState";
  }

  // OFFSET: LEGO1 0x1000e0e0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, HelicopterState::ClassName()) || LegoState::IsA(name);
  }
};

#endif // HELICOPTERSTATE_H
