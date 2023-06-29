#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "mxmediapresenter.h"

class MxVideoPresenter : public MxMediaPresenter
{
public:
  // OFFSET: LEGO1 0x1000c820
  inline virtual const char *ClassName() const override // vtable+0x0c
  { 
    // 0x100f0760
    return "MxVideoPresenter";
  }

  // OFFSET: LEGO1 0x1000c830
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxVideoPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  }
};

#endif // MXVIDEOPRESENTER_H
