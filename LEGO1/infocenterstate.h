#ifndef INFOCENTERSTATE_H
#define INFOCENTERSTATE_H

#include "legostate.h"

// VTABLE 0x100d93a8
// SIZE 0x94
class InfocenterState : public LegoState
{
public:
  InfocenterState();
  virtual ~InfocenterState();

  // OFFSET: LEGO1 0x10071840
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f04dc
    return "InfocenterState";
  }

  // OFFSET: LEGO1 0x10071850
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, InfocenterState::ClassName()) || LegoState::IsA(name);
  }
};

#endif // INFOCENTERSTATE_H
