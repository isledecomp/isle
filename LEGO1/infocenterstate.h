#ifndef INFOCENTERSTATE_H
#define INFOCENTERSTATE_H

#include "legostate.h"

class InfoCenterState : public LegoState
{
public:
  InfoCenterState();
  virtual ~InfoCenterState();

  // OFFSET: LEGO1 0x10071840
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f04dc
    return "InfoCenterState";
  }; 

  // OFFSET: LEGO1 0x10071850
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, InfoCenterState::GetClassName()) || LegoState::IsClass(name);
  };

  virtual MxBool VTable0x14();
  
  // VTABLE 0x100d93a8
  // SIZE 0x94
};

#endif // INFOCENTERSTATE_H