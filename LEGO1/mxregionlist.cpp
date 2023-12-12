#include "mxregionlist.h"

#include "mxregion.h"

// FUNCTION: LEGO1 0x100c33e0
void MxRegionList::Destroy(MxRegionTopBottom* p_topBottom)
{
	if (p_topBottom) {
		if (p_topBottom->m_leftRightList)
			delete p_topBottom->m_leftRightList;
		delete p_topBottom;
	}
}

// FUNCTION: LEGO1 0x100c4e80
void MxRegionLeftRightList::Destroy(MxRegionLeftRight* p_leftRight)
{
	delete p_leftRight;
}
