#ifndef MXDSMEDIAACTION_H
#define MXDSMEDIAACTION_H

#include "decomp.h"
#include "mxdsaction.h"

// VTABLE 0x100dcd40
// SIZE 0xb8
class MxDSMediaAction : public MxDSAction
{
public:
  MxDSMediaAction();
  virtual ~MxDSMediaAction() override;

  // OFFSET: LEGO1 0x100c8be0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f7624
    return "MxDSMediaAction";
  }

  // OFFSET: LEGO1 0x100c8bf0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDSMediaAction::ClassName()) || MxDSAction::IsA(name);
  }
private:
  undefined* m_unk98;
  undefined* m_unk9c;
  undefined* m_unka0;
  undefined* m_unka4;
  undefined* m_unka8;
  undefined* m_unkb4;
  undefined* m_unkb0;
  undefined* m_unkac;
};

#endif // MXDSMEDIAACTION_H
