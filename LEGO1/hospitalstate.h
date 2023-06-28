#ifndef HOSPITALSTATE_H
#define HOSPITALSTATE_H

#include "legostate.h"

class HospitalState : public LegoState
{
public:
  HospitalState();

  // OFFSET: LEGO1 0x10076400
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f0480
    return "HospitalState";
  }; 

  // OFFSET: LEGO1 0x10076410
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, HospitalState::ClassName()) || LegoState::IsA(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param);
  
  // VTABLE 0x100d97a0	
  // SIZE 0x18
};

#endif // HOSPITALSTATE_H
