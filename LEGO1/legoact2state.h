#ifndef LEGOACT2STATE_H
#define LEGOACT2STATE_H

#include "legostate.h"

class LegoAct2State : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000df80
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f0428
    return "LegoAct2State";
  }; 

  // OFFSET: LEGO1 0x1000df90
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, LegoAct2State::ClassName()) || LegoState::IsA(name);
  };

  virtual MxBool VTable0x14();

  // SIZE 0x10
};

#endif // LEGOACT2STATE_H
