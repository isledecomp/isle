#ifndef CARRACESTATE_H
#define CARRACESTATE_H

#include "racestate.h"

class CarRaceState : public RaceState
{
public:
  // OFFSET: LEGO1 0x1000dd30
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f009c
    return "CarRaceState";
  }; 

  // OFFSET: LEGO1 0x1000dd40
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, CarRaceState::GetClassName()) || RaceState::IsClass(name);
  };
};

#endif // CARRACESTATE_H
