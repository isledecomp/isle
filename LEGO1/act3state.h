#ifndef ACT3STATE_H
#define ACT3STATE_H

#include "legostate.h"

class Act3State : public LegoState
{
public:
  Act3State();

  // OFFSET: LEGO1 0x1000e300
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    return "Act3State";
  }; 

  // OFFSET: LEGO1 0x100d4fd8
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, Act3State::GetClassName()) || LegoState::IsClass(name);
  };

  virtual MxBool VTable0x14();
};

#endif // ACT3STATE_H
