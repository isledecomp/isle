#ifndef MXCOMPOSITEMEDIAPRESENTER_H
#define MXCOMPOSITEMEDIAPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE 0x100dc618
// SIZE 0x50
class MxCompositeMediaPresenter : public MxCompositePresenter
{
public:
  MxCompositeMediaPresenter();

  // OFFSET: LEGO1 0x10073f10
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f02d4
    return "MxCompositeMediaPresenter";
  }

  // OFFSET: LEGO1 0x10073f20
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxCompositeMediaPresenter::ClassName()) || MxCompositePresenter::IsA(name);
  }
  
};

#endif // MXCOMPOSITEMEDIAPRESENTER_H
