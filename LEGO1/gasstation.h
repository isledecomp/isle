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
  
  undefined VTable0x64(undefined4 param); // vtable+0x64

  // VTABLE 0x100d4650
  // SIZE 0x128
  // Radio variable at 0x46, in constructor
};

#endif // GASSTATION_H
