#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "mxcore.h"

class LegoControlManager : public MxCore
{
public:
  virtual ~LegoControlManager(); // vtable+0x0

  virtual long Tickle(); // vtable+0x8
  virtual const char* ClassName() const; // vtable+0xc
  virtual MxBool IsA(const char *name) const; // vtable+0x10

  // VTABLE 0x100d6a80
};

#endif // LEGOCONTROLMANAGER_H
