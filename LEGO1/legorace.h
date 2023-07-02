#ifndef LEGORACE_H
#define LEGORACE_H

#include "legoworld.h"

// VTABLE 0x100d5db0
class LegoRace : public LegoWorld
{
public:
  LegoRace();
  virtual ~LegoRace() override; // vtable+0x0

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x10015ba0
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f07c4
    return "LegoRace";
  }

  // OFFSET: LEGO1 0x10015bb0
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoRace::ClassName()) || LegoWorld::IsA(name);
  }
};

#endif // LEGORACE_H
