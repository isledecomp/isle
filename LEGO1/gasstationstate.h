#ifndef GASSTATIONSTATE_H
#define GASSTATIONSTATE_H

#include "legostate.h"

// VTABLE 0x100d46e0
// SIZE 0x24
class GasStationState : public LegoState
{
public:
  GasStationState();

  // OFFSET: LEGO1 0x100061d0
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0174
    return "GasStationState";
  }

  // OFFSET: LEGO1 0x100061e0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, GasStationState::ClassName()) || LegoState::IsA(name);
  }

};

#endif // GASSTATIONSTATE_H
