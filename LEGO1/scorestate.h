#ifndef SCORESTATE_H
#define SCORESTATE_H

#include "legostate.h"

// VTABLE 0x100d53f8
// SIZE 0xc
class ScoreState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000de40
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0084
    return "ScoreState";
  }; 

  // OFFSET: LEGO1 0x1000de50
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, ScoreState::ClassName()) || LegoState::IsA(name);
  };

};

#endif // SCORESTATE_H
