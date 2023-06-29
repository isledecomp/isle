#ifndef LEGOPATHPRESENTER_H
#define LEGOPATHPRESENTER_H

#include "mxmediapresenter.h"

// VTABLE 0x100d7c10
// SIZE 0x54
class LegoPathPresenter : public MxMediaPresenter
{
public:
  LegoPathPresenter();

  // OFFSET: LEGO1 0x100449a0
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f0690
    return "LegoPathPresenter";
  }

  // OFFSET: LEGO1 0x100449b0
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoPathPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  }

};


#endif // LEGOPATHPRESENTER_H
