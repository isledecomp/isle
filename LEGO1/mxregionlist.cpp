#include "mxregionlist.h"

#include "mxregion.h"

// FUNCTION: LEGO1 0x100c32e0 SYNTHETIC
// MxCollection<MxRegionTopBottom *>::Compare

// FUNCTION: LEGO1 0x100c3340 SYNTHETIC
// MxCollection<MxRegionTopBottom *>::Destroy

// FUNCTION: LEGO1 0x100c33e0
void MxRegionList::Destroy(MxRegionTopBottom* p_topBottom)
{
	if (p_topBottom) {
		if (p_topBottom->m_leftRightList)
			delete p_topBottom->m_leftRightList;
		delete p_topBottom;
	}
}

// FUNCTION: LEGO1 0x100c34d0 SYNTHETIC
// MxCollection<MxRegionTopBottom *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c3540 SYNTHETIC
// MxList<MxRegionTopBottom *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c35f0 SYNTHETIC
// MxPtrList<MxRegionTopBottom>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c4d80 SYNTHETIC
// MxCollection<MxRegionLeftRight *>::Compare

// FUNCTION: LEGO1 0x100c4de0 SYNTHETIC
// MxCollection<MxRegionLeftRight *>::Destroy

// FUNCTION: LEGO1 0x100c4e80
void MxRegionLeftRightList::Destroy(MxRegionLeftRight* p_leftRight)
{
	delete p_leftRight;
}

// FUNCTION: LEGO1 0x100c4f50 SYNTHETIC
// MxCollection<MxRegionLeftRight *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c4fc0 SYNTHETIC
// MxList<MxRegionLeftRight *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c5070 SYNTHETIC
// MxPtrList<MxRegionLeftRight>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100c54f0 SYNTHETIC
// MxListCursor<MxRegionLeftRight *>::MxListCursor<MxRegionLeftRight *>

// FUNCTION: LEGO1 0x100c58c0 SYNTHETIC
// MxList<MxRegionLeftRight *>::_InsertEntry

// FUNCTION: LEGO1 0x100c5970 SYNTHETIC
// MxList<MxRegionTopBottom *>::_InsertEntry

// FUNCTION: LEGO1 0x100c5a20 SYNTHETIC
// MxListEntry<MxRegionTopBottom *>::MxListEntry<MxRegionTopBottom *>

// FUNCTION: LEGO1 0x100c5a40 SYNTHETIC
// MxList<MxRegionLeftRight *>::_DeleteEntry
