#include "mxregionlist.h"

#include "mxregion.h"

// TEMPLATE: LEGO1 0x100c32e0
// MxCollection<MxRegionTopBottom *>::Compare

// TEMPLATE: LEGO1 0x100c3340
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

// SYNTHETIC: LEGO1 0x100c34d0
// MxCollection<MxRegionTopBottom *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3540
// MxList<MxRegionTopBottom *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c35f0
// MxPtrList<MxRegionTopBottom>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4d80
// MxCollection<MxRegionLeftRight *>::Compare

// TEMPLATE: LEGO1 0x100c4de0
// MxCollection<MxRegionLeftRight *>::Destroy

// FUNCTION: LEGO1 0x100c4e80
void MxRegionLeftRightList::Destroy(MxRegionLeftRight* p_leftRight)
{
	delete p_leftRight;
}

// SYNTHETIC: LEGO1 0x100c4f50
// MxCollection<MxRegionLeftRight *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c4fc0
// MxList<MxRegionLeftRight *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c5070
// MxPtrList<MxRegionLeftRight>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c54f0
// MxListCursor<MxRegionLeftRight *>::MxListCursor<MxRegionLeftRight *>

// TEMPLATE: LEGO1 0x100c58c0
// MxList<MxRegionLeftRight *>::_InsertEntry

// TEMPLATE: LEGO1 0x100c5970
// MxList<MxRegionTopBottom *>::_InsertEntry

// TEMPLATE: LEGO1 0x100c5a20
// MxListEntry<MxRegionTopBottom *>::MxListEntry<MxRegionTopBottom *>

// TEMPLATE: LEGO1 0x100c5a40
// MxList<MxRegionLeftRight *>::_DeleteEntry
