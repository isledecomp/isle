#ifndef GASSTATIONSTATE_H
#define GASSTATIONSTATE_H

#include "legostate.h"

class GasStationState : public LegoState
{
public:
  GasStationState();

  // OFFSET: LEGO1 0x100061d0
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f0174
    return "GasStationState";
  }; 

  // OFFSET: LEGO1 0x100061e0
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, GasStationState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param);

  // field 0x8 is prob MxResult
  // field 0xc is prob MxResult
  // field 0x10 is prob MxResult
};

#endif // GASSTATIONSTATE_H
