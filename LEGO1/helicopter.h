#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "islepathactor.h"

class Helicopter : public IslePathActor
{
public:
  Helicopter();
  virtual ~Helicopter(); // vtable+0x0

  virtual const char* GetClassName() const; // vtable+0x
  virtual MxBool IsClass(const char *name) const; // vtable+0x

  virtual void FUN_10003ee0(float param_1); // 0x70
  virtual void __fastcall FUN_10003360(int* param); // vtable+0xe4

  // VTABLE 0x100d40f8
};

#endif // HELICOPTER_H
