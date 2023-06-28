#ifndef ANIMSTATE_H
#define ANIMSTATE_H

#include "legostate.h"

class AnimState : public LegoState
{
public:
  AnimState();
  virtual ~AnimState(); // vtable+0x0

  // OFFSET: LEGO1 0x10065070
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f0460
    return "AnimState";
  }; 

  // OFFSET: LEGO1 0x10065080
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, AnimState::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x18(); // vtable+0x18
  virtual undefined4 VTable0x1c(undefined4 param); // vtable+0x1c
  
  // VTABLE 0x100d8d80
  // SIZE 0x1c
};

#endif // ANIMSTATE_H