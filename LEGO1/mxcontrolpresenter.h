#ifndef MXCONTROLPRESENTER_H
#define MXCONTROLPRESENTER_H

#include "decomp.h"

#include "mxcompositepresenter.h"

// VTABLE 0x100d7b88
// SIZE 0x5c
class MxControlPresenter : public MxCompositePresenter
{
public:
  MxControlPresenter();

  // OFFSET: LEGO1 0x10044000
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f0514
    return "MxControlPresenter";
  }

  // OFFSET: LEGO1 0x10044010
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxControlPresenter::ClassName()) || MxCompositePresenter::IsA(name);
  }
private:
  MxS16 m_unk4c;
  MxS16 m_unk4e;
  undefined m_unk50;
  undefined m_unk51;
  MxS16 m_unk52;
  MxS16 m_unk54;
  undefined2 m_unk56;
  MxS32 m_unk58;
};


#endif // MXCONTROLPRESENTER_H
