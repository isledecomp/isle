#ifndef GASSTATION_H
#define GASSTATION_H

#include "legoworld.h"

// VTABLE 0x100d4650
// SIZE 0x128
// Radio variable at 0x46, in constructor
class GasStation : public LegoWorld
{
public:
  GasStation();
  virtual ~GasStation() override; // vtable+0x0
  
  virtual long Notify(MxParam &p) override; // vtable+0x4
  virtual long Tickle() override; // vtable+0x8

  // OFFSET: LEGO1 0x10004780
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0168
    return "GasStation";
  }

  // OFFSET: LEGO1 0x10004790
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, GasStation::ClassName()) || LegoWorld::IsA(name);
  }

};

#endif // GASSTATION_H
