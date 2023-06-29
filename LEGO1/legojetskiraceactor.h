#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legocarraceactor.h"

// VTABLE 0x100da240
class LegoJetskiRaceActor : public LegoCarRaceActor
{
public:
  // OFFSET: LEGO1 0x10081d80
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0554
    return "LegoJetskiRaceActor";
  }

  // OFFSET: LEGO1 0x10081da0
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoJetskiRaceActor::ClassName()) || LegoCarRaceActor::IsA(name);
  }
};

#endif // LEGOJETSKIRACEACTOR_H
