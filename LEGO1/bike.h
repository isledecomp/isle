#ifndef BIKE_H
#define BIKE_H

#include "islepathactor.h"

#ifndef undefined4
#define undefined4 int
#endif

class Bike : public IslePathActor
{
public:
  Bike();

  virtual undefined4 VTable0xcc(); // vtable+0xcc
  virtual undefined4 VTable0xd4(undefined4 param); // vtable+0xd4
  virtual void VTable0xe4(); // vtable+0xe4

  // VTABLE 0x100d9808
  // SIZE 0x74
};


#endif // BIKE_H
