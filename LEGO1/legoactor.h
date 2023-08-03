#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

// VTABLE 0x100d6d68
// SIZE 0x78
class LegoActor : public LegoEntity
{
public:
  // OFFSET: LEGO1 0x1002d210
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0124
    return "LegoActor";
  }

  // OFFSET: LEGO1 0x1002d220
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoActor::ClassName()) || LegoEntity::IsA(name);
  }

private:
  undefined unk04_[0x68];

};

#endif // LEGOACTOR_H
