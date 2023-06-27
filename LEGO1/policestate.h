#ifndef POLICESTATE_H
#define POLICESTATE_H

#include "legostate.h"

class PoliceState : public LegoState
{
public:
  PoliceState();

  // OFFSET: LEGO1 0x1005e860
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f0444
    return "PoliceState";
  }; 

  // OFFSET: LEGO1 0x1005e870
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, PoliceState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param);
  
  // VTABLE 0x100d8af0
  // SIZE 0x10
};

#endif // POLICESTATE_H