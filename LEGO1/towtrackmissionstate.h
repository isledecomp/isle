#ifndef TOWTRACKMISSIONSTATE_H
#define TOWTRACKMISSIONSTATE_H

#include "legostate.h"

class TowTrackMissionState : LegoState
{
public:
  TowTrackMissionState();

  // OFFSET: LEGO1 0x1004dfa0
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f00bc
    return "TowTrackMissionState";
  }; 

  // OFFSET: LEGO1 0x1004dfb0
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, TowTrackMissionState::ClassName()) || LegoState::IsA(name);
  };

  virtual undefined4 VTable0x1c(undefined4 param); // vtable+0x1c

  // VTABLE 0x100d7fd8
  // SIZE 0x28
};

#endif // TOWTRACKMISSIONSTATE_H
