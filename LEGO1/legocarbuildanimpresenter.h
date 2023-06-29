#ifndef LEGOCARBUILDANIMPRESENTER_H
#define LEGOCARBUILDANIMPRESENTER_H

#include "legoanimpresenter.h"

// VTABLE 0x100d99e0
// SIZE 0x150
class LegoCarBuildAnimPresenter : public LegoAnimPresenter
{
public:
  LegoCarBuildAnimPresenter();
  virtual ~LegoCarBuildAnimPresenter() override; // vtable+0x0

  // OFFSET: LEGO1 0x10078510
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f05ec
    return "LegoCarBuildAnimPresenter";
  }

  // OFFSET: LEGO1 0x10078520
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoCarBuildAnimPresenter::ClassName()) || LegoAnimPresenter::IsA(name);
  }
};

#endif // LEGOCARBUILDANIMPRESENTER_H
