#ifndef HOSPITALSTATE_H
#define HOSPITALSTATE_H

#include "legostate.h"

// VTABLE 0x100d97a0
// SIZE 0x18
class HospitalState : public LegoState
{
public:
  HospitalState();

  // OFFSET: LEGO1 0x10076400
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0480
    return "HospitalState";
  }

  // OFFSET: LEGO1 0x10076410
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, HospitalState::ClassName()) || LegoState::IsA(name);
  }

};

#endif // HOSPITALSTATE_H
