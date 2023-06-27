#ifndef SCORESTATE_H
#define SCORESTATE_H

#include "legostate.h"

class ScoreState : public LegoState
{
public:
  // OFFSET: LEGO1 0x1000de40
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f0084
    return "ScoreState";
  }; 

  // OFFSET: LEGO1 0x1000de50
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, ScoreState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual MxBool VTable0x14();
  virtual MxBool VTable0x18();

  // SIZE 0xc
};

#endif // SCORESTATE_H
