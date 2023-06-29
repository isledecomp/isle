#ifndef AMBULANCE_H
#define AMBULANCE_H

#include "islepathactor.h"

// VTABLE 0x100d71a8
// SIZE 0x184
class Ambulance : public IslePathActor
{
public:
  Ambulance();

  // OFFSET: LEGO1 0x10035fa0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f03c4
    return "Ambulance";
  }

  // OFFSET: LEGO1 0x10035fb0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, Ambulance::ClassName()) || IslePathActor::IsA(name);
  }

};

#endif // AMBULANCE_H
