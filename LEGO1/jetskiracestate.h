#ifndef JETSKIRACESTATE_H
#define JETSKIRACESTATE_H

#include "racestate.h"

// VTABLE 0x100d4fa8
// SIZE 0x2c
class JetskiRaceState : public RaceState
{
public:
  // OFFSET: LEGO1 0x1000dc40
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f00ac
    return "JetskiRaceState";
  }

  // OFFSET: LEGO1 0x1000dc50
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, JetskiRaceState::ClassName()) || RaceState::IsA(name);
  }

};

#endif // JETSKIRACESTATE_H
