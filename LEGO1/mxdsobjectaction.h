#ifndef MXDSOBJECTACTION_H
#define MXDSOBJECTACTION_H

#include "mxdsmediaaction.h"

// VTABLE 0x100dccf8
// SIZE 0xb8
class MxDSObjectAction : public MxDSMediaAction
{
public:
  MxDSObjectAction();
  virtual ~MxDSObjectAction() override;

  // OFFSET: LEGO1 0x100c88e0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x101025c4
    return "MxDSObjectAction";
  }

  // OFFSET: LEGO1 0x100c88f0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSObjectAction::ClassName()) || MxDSMediaAction::IsA(name);
  }
};

#endif // MXDSOBJECTACTION_H
