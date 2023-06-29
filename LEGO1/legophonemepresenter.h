#ifndef LEGOPHONEMEPRESENTER_H
#define LEGOPHONEMEPRESENTER_H

#include "mxflcpresenter.h"

// VTABLE 0x100d8040
// SIZE 0x88
class LegoPhonemePresenter : public MxFlcPresenter
{
public:
  LegoPhonemePresenter();
  virtual ~LegoPhonemePresenter() override; // vtable+0x0

  // OFFSET: LEGO1 0x1004e310
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f064c
    return "LegoPhonemePresenter";
  }

private:
  void Init();

};

#endif // LEGOPHONEMEPRESENTER_H
