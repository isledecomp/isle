#ifndef MXEVENTPRESENTER_H
#define MXEVENTPRESENTER_H

#include "mxmediapresenter.h"

#include "decomp.h"

// VTABLE 0x100dca88
// SIZE 0x54
class MxEventPresenter : public MxMediaPresenter
{
public:
  MxEventPresenter();
  virtual ~MxEventPresenter() override;

  // OFFSET: LEGO1 0x100c2c30
  inline virtual const char* ClassName() const override // vtable+0xc
  {
    // 0x10101dcc
    return "MxEventPresenter";
  }

  // OFFSET: LEGO1 0x100c2c40
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxEventPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  }

private:
  void Init();
  void Destroy();

  undefined4 m_unk50;

};

#endif // MXEVENTPRESENTER_H
