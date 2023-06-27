#ifndef JUKEBOXSTATE_H
#define JUKEBOXSTATE_H

#include "legostate.h"

class JukeBoxState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000f310
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f02bc
    return "JukeBoxState";
  }; 

  // OFFSET: LEGO1 0x1000f320
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, JukeBoxState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual MxBool VTable0x14();

  // VTABLE 0x100d4a90
  // SIZE 0x10
};

#endif // JUKEBOXSTATE_H