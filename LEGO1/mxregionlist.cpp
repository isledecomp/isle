#include "mxregionlist.h"
#include "mxregion.h"

// OFFSET: LEGO1 0x100c4e80
void MxRegionLeftRightListParent::Destroy(MxRegionLeftRight *p_leftRight)
{
  delete p_leftRight;
}

// OFFSET: LEGO1 0x100c33e0
void MxRegionListParent::Destroy(MxRegionTopBottom *p_topBottom)
{
  if (p_topBottom) {
    if (p_topBottom->m_leftRightList)
      delete p_topBottom->m_leftRightList;
    delete p_topBottom;
  }
}