#ifndef MXDSMULTIACTION_H
#define MXDSMULTIACTION_H

#include "mxdsaction.h"

// VTABLE 0x100dcef0
// SIZE 0x9c
class MxDSMultiAction : public MxDSAction
{
public:
  MxDSMultiAction();
  virtual ~MxDSMultiAction() override;

  // OFFSET: LEGO1 0x100c9f50
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x10101dbc
    return "MxDSMultiAction";
  }

  // OFFSET: LEGO1 0x100c9f60
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSMultiAction::ClassName()) || MxDSAction::IsA(name);
  }
};

#endif // MXDSMULTIACTION_H
