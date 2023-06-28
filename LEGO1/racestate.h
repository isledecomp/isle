#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

class RaceState : public LegoState
{
public:
  RaceState();

  // OFFSET: LEGO1 0x10016010
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f07d0
    return "RaceState";
  }; 

  // OFFSET: LEGO1 0x10016020
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, RaceState::ClassName()) || LegoState::IsA(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param);
};

#endif // RACESTATE_H
