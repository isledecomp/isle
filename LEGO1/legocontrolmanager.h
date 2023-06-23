#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "mxcore.h"

class LegoControlManager : public MxCore
{
public:
  virtual ~LegoControlManager(); // vtable+0x0

  virtual const char* GetClassName() const; // vtable+0xc
  virtual MxBool IsClass(const char *name) const; // vtable+0x10

  // VTABLE 0x100d6a80
};

#endif // LEGOCONTROLMANAGER_H
