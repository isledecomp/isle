#include "mxdsactionlist.h"

#include "mxdsaction.h"

DECOMP_SIZE_ASSERT(MxDSActionList, 0x1c);
DECOMP_SIZE_ASSERT(MxDSActionListCursor, 0x10);

// FUNCTION: LEGO1 0x100c9c90
MxS8 MxDSActionList::Compare(MxDSAction* p_a, MxDSAction* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x100c9cb0
void MxDSActionList::Destroy(MxDSAction* p_action)
{
	if (p_action)
		delete p_action;
}

// TEMPLATE: LEGO1 0x100c9cc0
// MxCollection<MxDSAction *>::Compare

// TEMPLATE: LEGO1 0x100c9d20
// MxCollection<MxDSAction *>::Destroy

// TEMPLATE: LEGO1 0x100c9d30
// MxList<MxDSAction *>::~MxList<MxDSAction *>

// SYNTHETIC: LEGO1 0x100c9e30
// MxCollection<MxDSAction *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c9ea0
// MxList<MxDSAction *>::`scalar deleting destructor'
