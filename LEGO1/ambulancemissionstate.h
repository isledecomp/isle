#ifndef AMBULANCEMISSIONSTATE_H
#define AMBULANCEMISSIONSTATE_H

#include "legostate.h"

class AmbulanceMissionState : public LegoState
{
public:
  AmbulanceMissionState();

  // OFFSET: LEGO1 0x10037600
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f00e8
    return "AmbulanceMissionState";
  }; 

  // OFFSET: LEGO1 0x10037610
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, AmbulanceMissionState::ClassName()) || LegoState::IsA(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param);

  // VTABLE 0x100d72a0
  // SIZE 0x24
};


#endif // AMBULANCEMISSIONSTATE_H
