#ifndef MXDSSERIALACTION_H
#define MXDSSERIALACTION_H

#include "mxdsmultiaction.h"

// VTABLE 0x100dcf38
// SIZE 0xa8
class MxDSSerialAction : public MxDSMultiAction
{
public:
  MxDSSerialAction();
  virtual ~MxDSSerialAction() override;

  // OFFSET: LEGO1 0x100caad0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f75dc
    return "MxDSSerialAction";
  }

  // OFFSET: LEGO1 0x100caae0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSSerialAction::ClassName()) || MxDSMultiAction::IsA(name);
  }
};

#endif // MXDSSERIALACTION_H
