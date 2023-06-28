#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

class IsleActor : public LegoActor
{
public:
  virtual long Notify(MxParam &p); // vtable+0x4
  virtual const char* ClassName() const; // vtable+0xc
  virtual MxBool IsA(const char *name) const; // vtable+0x10

  // VTABLE 0x100d5178
};

#endif // ISLEACTOR_H
