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
  MxS32* m_unk94;
  MxS32* m_unk98;
  MxS32* m_unk9c;
  MxS32* m_unka0;
  MxS32* m_unka4;
  MxS32* m_unka8;
  MxS32* m_unkac;
  MxS32* m_unkb0;
  MxS32* m_unkb4;
};

#endif // MXDSMEDIAACTION_H
