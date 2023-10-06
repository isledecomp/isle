#ifndef MXLOOPINGSMKPRESENTER_H
#define MXLOOPINGSMKPRESENTER_H

#include "mxsmkpresenter.h"

#include "decomp.h"

// VTABLE 0x100dc540
// SIZE 0x724
class MxLoopingSmkPresenter : public MxSmkPresenter
{
public:
  MxLoopingSmkPresenter();
  virtual ~MxLoopingSmkPresenter() override; // vtable+0x0

  // OFFSET: LEGO1 0x100b4920
  inline virtual const char* ClassName() const override // vtable+0xc
  {
    // 0x10101e08
    return "MxLoopingSmkPresenter";
  }

private:
  void Init();
  void Destroy(MxBool);

  undefined4 m_unk720;
};

#endif // MXLOOPINGSMKPRESENTER_H
