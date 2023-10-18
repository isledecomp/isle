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

// OFFSET: LEGO1 0x100c3750
void MxRegion::vtable18(MxRect32 &p_rect)
{
  MxRect32 rectCopy(p_rect.m_left, p_rect.m_top, p_rect.m_right, p_rect.m_bottom);
  MxRegionListCursor cursor(m_list);

  if (rectCopy.m_left < rectCopy.m_right) {
    MxRegionTopBottom *topBottom;
    while (rectCopy.m_top < rectCopy.m_bottom && cursor.Next(topBottom)) {
      if (topBottom->m_top >= rectCopy.m_bottom) {
        MxRegionTopBottom *newTopBottom = new MxRegionTopBottom(rectCopy);
        cursor.Prepend(newTopBottom);
        rectCopy.m_top = rectCopy.m_bottom;
      }
      else {
        if (rectCopy.m_top < topBottom->m_bottom) {
          if (rectCopy.m_top < topBottom->m_top) {
            MxRect32 topBottomRect(rectCopy.m_left, rectCopy.m_top, rectCopy.m_right, topBottom->m_top);
            MxRegionTopBottom *newTopBottom = new MxRegionTopBottom(topBottomRect);
            cursor.Prepend(newTopBottom);
            rectCopy.m_top = topBottom->m_top;
          }
          else if (topBottom->m_top < rectCopy.m_top) {
            MxRegionTopBottom *newTopBottom = topBottom->Clone();
            newTopBottom->m_bottom = rectCopy.m_top;
            topBottom->m_top = rectCopy.m_top;
            cursor.Prepend(newTopBottom);
          }

          if (rectCopy.m_bottom < topBottom->m_top) {
            MxRegionTopBottom *newTopBottom = topBottom->Clone();
            newTopBottom->m_bottom = rectCopy.m_bottom;
            topBottom->m_top = rectCopy.m_bottom;
            newTopBottom->FUN_100c5280(rectCopy.m_left, rectCopy.m_right);
            cursor.Prepend(newTopBottom);
            rectCopy.m_top = rectCopy.m_bottom; 
          }
          else {
            topBottom->FUN_100c5280(rectCopy.m_left, rectCopy.m_right);
            rectCopy.m_top = topBottom->m_top;
          }
        }
      }

      if (rectCopy.m_right <= rectCopy.m_left)
        break;
    }
  }

  if (rectCopy.m_left < rectCopy.m_right && rectCopy.m_top < rectCopy.m_bottom) {
    MxRegionTopBottom *newTopBottom = new MxRegionTopBottom(rectCopy);
    m_list->OtherAppend(newTopBottom);
  }

  m_rect.m_left = m_rect.m_left <= p_rect.m_left ? m_rect.m_left : p_rect.m_left;
  m_rect.m_top = m_rect.m_top <= p_rect.m_top ? m_rect.m_top : p_rect.m_top;
  m_rect.m_right = m_rect.m_right <= p_rect.m_right ? p_rect.m_right : m_rect.m_right;
  m_rect.m_bottom = m_rect.m_bottom <= p_rect.m_bottom ? p_rect.m_bottom : m_rect.m_bottom;
}

// OFFSET: LEGO1 0x100c3e20 STUB
void MxRegion::vtable1c()
{
  // TODO
}

// OFFSET: LEGO1 0x100c50e0 STUB
MxRegionTopBottom::MxRegionTopBottom(MxRect32 &p_rect)
{

}

// OFFSET: LEGO1 0x100c5280 STUB
void MxRegionTopBottom::FUN_100c5280(MxS32 p_left, MxS32 p_right)
{

}

// OFFSET: LEGO1 0x100c55d0 STUB
MxRegionTopBottom *MxRegionTopBottom::Clone()
{
  return new MxRegionTopBottom(MxRect32());
}