#ifndef MOTORCYCLE_H
#define MOTORCYCLE_H

#include "islepathactor.h"

// VTABLE 0x100d7090
// SIZE 0x16c
class Motorcycle : public IslePathActor
{
public:
  Motorcycle();

  // OFFSET: LEGO1 0x10035840
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10035840
    return "Motorcycle";
  }

  // OFFSET: LEGO1 0x10035850
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Motorcycle::ClassName()) || IslePathActor::IsA(name);
  }

};

#endif // MOTORCYCLE_H
