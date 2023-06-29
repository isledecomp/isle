#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "legoworld.h"

// VTABLE 0x100d5f20
class ElevatorBottom : public LegoWorld
{
public:
  ElevatorBottom();
  virtual ~ElevatorBottom() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x10017f20
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f04ac
    return "ElevatorBottom";
  }

  // OFFSET: LEGO1 0x10017f30
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, ElevatorBottom::ClassName()) || LegoWorld::IsA(name);
  }

};

#endif // ELEVATORBOTTOM_H
