#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "islepathactor.h"

class Helicopter : public IslePathActor
{
public:
  Helicopter();
  virtual ~Helicopter(); // vtable+0x0

  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  virtual void VTable0x70(float param_1); // vtable+0x70
  virtual void VTable0xe4(); // vtable+0xe4

  // VTABLE 0x100d40f8
};

#endif // HELICOPTER_H
