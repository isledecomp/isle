#include "mxregion.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxRegion, 0x1c);
DECOMP_SIZE_ASSERT(MxRegionTopBottom, 0x0c);
DECOMP_SIZE_ASSERT(MxRegionLeftRight, 0x08);

// OFFSET: LEGO1 0x100c31c0
MxRegion::MxRegion()
{
  m_list = new MxRegionList;
  m_rect.m_left = INT_MAX;
  m_rect.m_top = INT_MAX;
  m_rect.m_right = -1;
  m_rect.m_bottom = - 1;
}

// OFFSET: LEGO1 0x100c3660 STUB
MxBool MxRegion::vtable20()
{
  // TODO
  return FALSE;
}

// OFFSET: LEGO1 0x100c3690 STUB
MxRegion::~MxRegion()
{
  // TODO
}

// OFFSET: LEGO1 0x100c3700 STUB
void MxRegion::Reset()
{
  // TODO
}

// OFFSET: LEGO1 0x100c3750 STUB
void MxRegion::vtable18(MxRect32 &p_rect)
{
  // TODO
}

// OFFSET: LEGO1 0x100c3e20 STUB
void MxRegion::vtable1c()
{
  // TODO
}
