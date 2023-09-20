#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "mxmediapresenter.h"

#include "decomp.h"

class MxVideoPresenter : public MxMediaPresenter
{
public:
  MxVideoPresenter()
  {
    Init();
  }

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

  void Init();

  undefined4 m_unk50;
  undefined4 m_unk54;
  undefined4 m_unk58;
  undefined2 m_unk5c;
  unsigned char m_flags; // 0x5e
  undefined4 m_unk60;
};

#endif // MXVIDEOPRESENTER_H
