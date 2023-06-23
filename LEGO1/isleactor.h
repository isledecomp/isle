#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoentity.h"

class IsleActor : public LegoEntity
{
  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  // VTABLE 0x100d5178
};

#endif // ISLEACTOR_H
