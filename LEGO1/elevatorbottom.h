#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "legoworld.h"

#ifndef undefined4
#define undefined4 int
#endif

#ifndef undefined1
#define undefined1 char
#endif

class ElevatorBottom : public LegoWorld
{
public:
  ElevatorBottom();
  virtual ~ElevatorBottom(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual const char* ClassName() const; // vtable+0xc
  virtual MxBool IsA(const char *name) const; // vtable+0x10

  virtual undefined4 VTable0x5c(); // vtable+0x5c
  virtual void VTable0x68(undefined1 param_1); // vtable+0x68

  // VTABLE 0x100d5f20
};

#endif // ELEVATORBOTTOM_H
