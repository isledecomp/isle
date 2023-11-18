#include "mxregionlist.h"

#include "mxregion.h"

// OFFSET: LEGO1 0x100c33e0
void MxRegionList::Destroy(MxRegionTopBottom* p_topBottom)
{
	if (p_topBottom) {
		if (p_topBottom->m_leftRightList)
			delete p_topBottom->m_leftRightList;
		delete p_topBottom;
	}
}

// OFFSET: LEGO1 0x100c4e80
void MxRegionLeftRightList::Destroy(MxRegionLeftRight* p_leftRight)
{
	delete p_leftRight;
}

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
