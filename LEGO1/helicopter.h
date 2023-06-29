#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "islepathactor.h"

// VTABLE 0x100d40f8
// SIZE 0x230
class Helicopter : public IslePathActor
{
public:
  Helicopter();
  virtual ~Helicopter(); // vtable+0x0

  // OFFSET: LEGO1 0x10003070
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0130
    return "Helicopter";
  }

  // OFFSET: LEGO1 0x10003080
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Helicopter::ClassName()) || IslePathActor::IsA(name);
  }

};

#endif // HELICOPTER_H
