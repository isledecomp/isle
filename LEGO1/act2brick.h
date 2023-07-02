#ifndef ACT2BRICK_H
#define ACT2BRICK_H

#include "legopathactor.h"

// VTABLE 0x100d9b60
// SIZE 0x194
class Act2Brick : public LegoPathActor
{
public:
  Act2Brick();
  virtual ~Act2Brick() override; // vtable+0x0

  virtual long Notify(MxParam &p) override; // vtable+0x4
  virtual long Tickle() override; // vtable+0x08

  // OFFSET: LEGO1 0x1007a360
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0438
    return "Act2Brick";
  }

  // OFFSET: LEGO1 0x1007a370
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(Act2Brick::ClassName(), name) || LegoEntity::IsA(name);
  }

};

#endif // ACT2BRICK_H
