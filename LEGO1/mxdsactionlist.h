#ifndef MXDSACTIONLIST_H
#define MXDSACTIONLIST_H

#include "decomp.h"
#include "mxlist.h"

class MxDSAction;

// VTABLE 0x100dced8
// SIZE 0x1c
class MxDSActionList : public MxList<MxDSAction*>
{
public:
  MxDSActionList() {
    this->m_unk18 = 0;
  }

  virtual MxS8 Compare(MxDSAction *, MxDSAction *); // +0x14

  static void Destroy(MxDSAction *p_action);

private:
  undefined m_unk18;
};

typedef MxListCursorChild<MxDSAction*> MxDSActionListCursor;

// OFFSET: LEGO1 0x100c9cc0 TEMPLATE
// MxListParent<MxDSAction *>::Compare

// OFFSET: LEGO1 0x100c9d20 TEMPLATE
// MxListParent<MxDSAction *>::Destroy

// OFFSET: LEGO1 0x100c9d30 TEMPLATE
// MxList<MxDSAction *>::~MxList<MxDSAction *>

#endif // MXDSACTIONLIST_H
