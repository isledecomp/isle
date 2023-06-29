#ifndef LEGOANIMMMPRESENTER_H
#define LEGOANIMMMPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE 0x100d7de8
// SIZE 0x74
class LegoAnimMMPresenter : public MxCompositePresenter
{
public:
  LegoAnimMMPresenter();

  // OFFSET: LEGO1 0x1004a950
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f046c
    return "LegoAnimMMPresenter";
  }

  // OFFSET: LEGO1 0x1004a960
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoAnimMMPresenter::ClassName()) || MxCompositePresenter::IsA(name);
  }

};

#endif // LEGOANIMMMPRESENTER_H
