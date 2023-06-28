#ifndef HELICOPTERSTATE_H
#define HELICOPTERSTATE_H

#include "legostate.h"

class HelicopterState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000e0d0
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f0144
    return "HelicopterState";
  }; 

  // OFFSET: LEGO1 0x100d5428
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, HelicopterState::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x14();
  virtual MxBool VTable0x18();
};

#endif // HELICOPTERSTATE_H
