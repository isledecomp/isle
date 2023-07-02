#ifndef JUKEBOXSTATE_H
#define JUKEBOXSTATE_H

#include "legostate.h"

// VTABLE 0x100d4a90
// SIZE 0x10
class JukeBoxState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000f310
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f02bc
    return "JukeBoxState";
  }

  // OFFSET: LEGO1 0x1000f320
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, JukeBoxState::ClassName()) || LegoState::IsA(name);
  }

};

#endif // JUKEBOXSTATE_H
