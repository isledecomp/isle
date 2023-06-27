#ifndef PIZZAMISSIONSTATE_H
#define PIZZAMISSIONSTATE_H

#include "legostate.h"

class PizzaMissionState : public LegoState
{
public:
  // OFFSET: LEGO1 0x10039290
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f00d4
    return "PizzaMissionState";
  }; 

  // OFFSET: LEGO1 0x100392a0
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, PizzaMissionState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual undefined4 VTable0x1c(undefinedPtr param);
};

#endif // PIZZAMISSIONSTATE_H
