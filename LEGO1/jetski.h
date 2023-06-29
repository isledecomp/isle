#ifndef JETSKI_H
#define JETSKI_H

#include "islepathactor.h"

// VTABLE 0x100d9ec8
// SIZE 0x164
class Jetski : public IslePathActor
{
public:
  Jetski();

  // OFFSET: LEGO1 0x1007e430
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f03d8
    return "Jetski";
  }

  // OFFSET: LEGO1 0x1007e440
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Jetski::ClassName()) || IslePathActor::IsA(name);
  }

};


#endif // JETSKI_H
