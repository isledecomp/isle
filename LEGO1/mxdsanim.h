#ifndef MXDSANIM_H
#define MXDSANIM_H

#include "mxdsmediaaction.h"

// VTABLE 0x100dcd88
// SIZE 0xb8
class MxDSAnim : public MxDSMediaAction
{
public:
  MxDSAnim();

  virtual ~MxDSAnim() override;

  // OFFSET: LEGO1 0x100c9060
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x101025d8
    return "MxDSAnim";
  }

  // OFFSET: LEGO1 0x100c9070
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSAnim::ClassName()) || MxDSMediaAction::IsA(name);
  }
};

#endif // MXDSANIM_H
