#ifndef JETSKIRACESTATE_H
#define JETSKIRACESTATE_H

#include "racestate.h"

class JetskiRaceState : public RaceState
{
public:
  // OFFSET: LEGO1 0x1000dc40
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f00ac
    return "JetskiRaceState";
  }; 

  // OFFSET: LEGO1 0x1000dc50
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, JetskiRaceState::GetClassName()) || RaceState::IsClass(name);
  };

  // VTABLE 0x100d4fa8
  // SIZE 0x2c
};

#endif // JETSKIRACESTATE_H
