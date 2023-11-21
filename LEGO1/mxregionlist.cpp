#include "mxregionlist.h"

#include "mxregion.h"

// OFFSET: LEGO1 0x100c32e0 TEMPLATE
// MxCollection<MxRegionTopBottom *>::Compare

// OFFSET: LEGO1 0x100c3340 TEMPLATE
// MxCollection<MxRegionTopBottom *>::Destroy

// OFFSET: LEGO1 0x100c33e0
void MxRegionList::Destroy(MxRegionTopBottom* p_topBottom)
{
	if (p_topBottom) {
		if (p_topBottom->m_leftRightList)
			delete p_topBottom->m_leftRightList;
		delete p_topBottom;
	}
}

// OFFSET: LEGO1 0x100c34d0 TEMPLATE
// MxCollection<MxRegionTopBottom *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c3540 TEMPLATE
// MxList<MxRegionTopBottom *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c35f0 TEMPLATE
// MxPtrList<MxRegionTopBottom>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c4d80 TEMPLATE
// MxCollection<MxRegionLeftRight *>::Compare

// OFFSET: LEGO1 0x100c4de0 TEMPLATE
// MxCollection<MxRegionLeftRight *>::Destroy

// OFFSET: LEGO1 0x100c4e80
void MxRegionLeftRightList::Destroy(MxRegionLeftRight* p_leftRight)
{
	delete p_leftRight;
}

// OFFSET: LEGO1 0x100c4f50 TEMPLATE
// MxCollection<MxRegionLeftRight *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c4fc0 TEMPLATE
// MxList<MxRegionLeftRight *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c5070 TEMPLATE
// MxPtrList<MxRegionLeftRight>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100c54f0 TEMPLATE
// MxListCursor<MxRegionLeftRight *>::MxListCursor<MxRegionLeftRight *>

// OFFSET: LEGO1 0x100c58c0 TEMPLATE
// MxList<MxRegionLeftRight *>::_InsertEntry

// OFFSET: LEGO1 0x100c5970 TEMPLATE
// MxList<MxRegionTopBottom *>::_InsertEntry

// OFFSET: LEGO1 0x100c5a20 TEMPLATE
// MxListEntry<MxRegionTopBottom *>::MxListEntry<MxRegionTopBottom *>

// OFFSET: LEGO1 0x100c5a40 TEMPLATE
// MxList<MxRegionLeftRight *>::_DeleteEntry
