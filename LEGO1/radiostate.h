#ifndef RADIOSTATE_H
#define RADIOSTATE_H

#include "legostate.h"

class RadioState : public LegoState
{
public:
  RadioState();

  // OFFSET: LEGO1 0x1002cf60
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f04f8
    return "RadioState";
  }; 

  // OFFSET: LEGO1 0x1002cf70
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, RadioState::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x14(); // vtable+0x14
  
  // VTABLE 0x100d6d28
  // SIZE 0x30
};

#endif // RADIOSTATE_H
