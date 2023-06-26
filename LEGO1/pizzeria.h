#ifndef PIZZERIASTATE_H
#define PIZZERIASTATE_H

#include "isleactor.h"

#ifndef undefined4
#define undefined4 int
#endif

class Pizzeria : public IsleActor
{
public:
  Pizzeria();

  virtual undefined4 VTable0x68(); // vtable+0x68

  // VTABLE 0x100d5520
  // SIZE 0x84
};

#endif // PIZZERIASTATE_H