#ifndef ISLE_H
#define ISLE_H

#include "legoworld.h"

#ifndef undefined4
#define undefined4 int
#endif

class Isle : public LegoWorld
{
public:
  Isle();

  virtual void VTable0x50(); // vtable+0x50
  virtual undefined4  VTable0x64(); // vtable+0x64
  virtual void VTable0x6c(int* param); // vtable+0x6c

  // VTABLE 0x100d6fb8
  // SIZE 0x140
  // Radio at 0x12c
};

#endif // ISLE_H
