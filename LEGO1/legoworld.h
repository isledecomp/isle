#ifndef LEGOWORLD_H
#define LEGOWORLD_H

#include "legoentity.h"

// VTABLE 0x100d6280
// SIZE 0xf8
class LegoWorld : public LegoEntity
{
public:
  __declspec(dllexport) LegoWorld();
  __declspec(dllexport) virtual ~LegoWorld(); // vtable+0x0

  // OFFSET: LEGO1 0x1001d690
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0058
    return "LegoWorld";
  }

  // OFFSET: LEGO1 0x1001d6a0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoWorld::ClassName()) || LegoEntity::IsA(name);
  }
};

#endif // LEGOWORLD_H
