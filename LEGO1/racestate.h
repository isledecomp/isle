#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

// VTABLE 0x100d5e30
// SIZE probably 0x2c
class RaceState : public LegoState
{
public:
  RaceState();

  // OFFSET: LEGO1 0x10016010
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f07d0
    return "RaceState";
  }

  // OFFSET: LEGO1 0x10016020
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, RaceState::ClassName()) || LegoState::IsA(name);
  }

};

#endif // RACESTATE_H
