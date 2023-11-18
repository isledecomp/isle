#include "mxdsactionlist.h"

#include "mxdsaction.h"

DECOMP_SIZE_ASSERT(MxDSActionList, 0x1c);
DECOMP_SIZE_ASSERT(MxDSActionListCursor, 0x10);

// OFFSET: LEGO1 0x100c9c90
MxS8 MxDSActionList::Compare(MxDSAction* p_a, MxDSAction* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// OFFSET: LEGO1 0x100c9cb0
void MxDSActionList::Destroy(MxDSAction* p_action)
{
	if (p_action)
		delete p_action;
}

// OFFSET: LEGO1 0x100c9cc0 TEMPLATE
// MxCollection<MxDSAction *>::Compare

// OFFSET: LEGO1 0x100c9d20 TEMPLATE
// MxCollection<MxDSAction *>::Destroy

// OFFSET: LEGO1 0x100c9d30 TEMPLATE
// MxList<MxDSAction *>::~MxList<MxDSAction *>

// OFFSET: LEGO1 0x100c9e30 TEMPLATE
// MxCollection<MxDSAction *>::~MxCollection<MxDSAction *>

// OFFSET: LEGO1 0x100c9ea0 TEMPLATE
// MxList<MxDSAction *>::~MxList<MxDSAction *>
