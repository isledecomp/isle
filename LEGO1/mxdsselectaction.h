#ifndef MXDSSELECTACTION_H
#define MXDSSELECTACTION_H

#include "mxdsparallelaction.h"

// VTABLE 0x100dcfc8
// SIZE 0xb0
class MxDSSelectAction : public MxDSParallelAction
{
public:
  MxDSSelectAction();
  virtual ~MxDSSelectAction() override;

  // OFFSET: LEGO1 0x100cb6f0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x1010261c
    return "MxDSSelectAction";
  }

  // OFFSET: LEGO1 0x100cb700
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSSelectAction::ClassName()) || MxDSParallelAction::IsA(name);
  }

};

#endif // MXDSSELECTACTION_H
