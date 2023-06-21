#ifndef BIKE_H
#define BIKE_H

#include "islepathactor.h"

class Bike : public IslePathActor
{
public:
  Bike();

  virtual int __fastcall FUN_100769a0(int*); // vtable+0xcc , return is undefined 4-byte value
  virtual int FUN_10076aa0(int param_1); // vtable+0xd4 , return is undefined 4-byte value
  virtual void __fastcall FUN_10076920(int* param_1); // vtable+0xe4

  // VTABLE 0x100d9808
  // SIZE 0x74
};


#endif // BIKE_H
