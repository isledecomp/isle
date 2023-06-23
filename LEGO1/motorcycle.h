#ifndef MOTORCYCLE_H
#define MOTORCYCLE_H

#include "islepathactor.h"

class Motorcycle : public IslePathActor
{
public:
  Motorcycle();

  virtual void VTable0xcc(); // vtable+0xcc
  virtual void VTable0xe4(); // vtable+0xe4

  // VTABLE 0x100d7090
  // SIZE 0x16c
};

#endif // MOTORCYCLE_H
