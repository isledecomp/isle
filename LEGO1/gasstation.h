#ifndef GASSTATION_H
#define GASSTATION_H

#include "legoworld.h"

#ifndef undefined
#define undefined int
#endif

#ifndef undefined4
#define undefined4 int
#endif

class GasStation : public LegoWorld
{
public:
  GasStation();
  virtual ~GasStation(); // vtable+0x0
  
  virtual long Notify(MxParam &p); // vtable+0x4
  virtual long Tickle(); // vtable+0x8
  undefined VTable0x64(undefined4 param); // vtable+0x64

  // VTABLE 0x100d4650
  // SIZE 0x128
  // Radio variable at 0x46, in constructor
};

#endif // GASSTATION_H
