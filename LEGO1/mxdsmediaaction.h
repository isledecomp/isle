#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "mxdsaction.h"

// VTABLE 0x100dcd40
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction
{
public:
  MxDSMediaAction();
  virtual ~MxDSMediaAction() override;

  // OFFSET: LEGO1 0x100c8be0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f7624
    return "MxDSMediaAction";
  }

  // OFFSET: LEGO1 0x100c8bf0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(name);
  }

};

#endif // MXDSMEDIAACTION_H
