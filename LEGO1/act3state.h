#ifndef ACT3STATE_H
#define ACT3STATE_H

#include "legostate.h"

class Act3State : public LegoState
{
public:
  Act3State();

  // OFFSET: LEGO1 0x1000e300
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    return "Act3State";
  }; 

  // OFFSET: LEGO1 0x100d4fd8
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, Act3State::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x14();
};

#endif // ACT3STATE_H
