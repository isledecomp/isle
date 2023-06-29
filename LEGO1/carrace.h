#ifndef CARRACE_H
#define CARRACE_H

#include "legorace.h"

// VTABLE 0x100d5e50
// SIZE 0x154
class CarRace : public LegoRace
{
public:
  CarRace();

  // OFFSET: LEGO1 0x10016b20
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0528
    return "CarRace";
  }

  // OFFSET: LEGO1 0x10016b30
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, CarRace::ClassName()) || LegoRace::IsA(name);
  }
};

#endif // CARRACE_H
