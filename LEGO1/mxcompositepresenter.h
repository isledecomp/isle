#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"

// VTABLE 0x100dc618
// SIZE 0x4c
class MxCompositePresenter : public MxPresenter
{
public:
  MxCompositePresenter();
  virtual ~MxCompositePresenter() override; // vtable+0x0

  // OFFSET: LEGO1 0x100b6210
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0774
    return "MxCompositePresenter";
  }

  // OFFSET: LEGO1 0x100b6220
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxCompositePresenter::ClassName()) || MxPresenter::IsA(name);
  }

  undefined m_unk40;
  undefined4 *m_unk44;
  undefined4 m_unk48;
};

#endif // MXCOMPOSITEPRESENTER_H
