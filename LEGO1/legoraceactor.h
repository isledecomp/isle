#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"

// VTABLE 0x100d5b88
class LegoRaceActor : public LegoAnimActor
{
public:
  // OFFSET: LEGO1 0x10014af0
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0bf4
    return "LegoRaceActor";
  }

  // OFFSET: LEGO1 0x10014b10
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoRaceActor::ClassName()) || LegoAnimActor::IsA(name);
  }
};


#endif // LEGORACEACTOR_H
