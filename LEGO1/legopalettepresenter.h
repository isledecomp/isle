#ifndef LEGOPALETTEPRESENTER_H
#define LEGOPALETTEPRESENTER_H

#include "mxvideopresenter.h"

// VTABLE 0x100d9aa0
// SIZE 0x68
class LegoPalettePresenter : public MxVideoPresenter
{
public:
  LegoPalettePresenter();
  virtual ~LegoPalettePresenter(); // vtable+0x0

  // OFFSET: LEGO1 0x10079f30
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f061c
    return "LegoPalettePresenter";
  }

  // OFFSET: LEGO1 0x10079f40
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, ClassName()) || MxVideoPresenter::IsA(name);
  }

private:
  void Init();

};


#endif // LEGOPALETTEPRESENTER_H
