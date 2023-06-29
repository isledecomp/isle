#ifndef PIZZAMISSIONSTATE_H
#define PIZZAMISSIONSTATE_H

#include "legostate.h"

// VTABLE 0x100d7408
class PizzaMissionState : public LegoState
{
public:
  // OFFSET: LEGO1 0x10039290
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f00d4
    return "PizzaMissionState";
  }

  // OFFSET: LEGO1 0x100392a0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, PizzaMissionState::ClassName()) || LegoState::IsA(name);
  }

};

#endif // PIZZAMISSIONSTATE_H
