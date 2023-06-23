#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

class IsleActor : public LegoActor
{
  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  // VTABLE 0x100d5178
};

#endif // ISLEACTOR_H
