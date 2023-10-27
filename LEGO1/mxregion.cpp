#include "mxregion.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxRegion, 0x1c);
DECOMP_SIZE_ASSERT(MxRegionTopBottom, 0x0c);
DECOMP_SIZE_ASSERT(MxRegionLeftRight, 0x08);

// OFFSET: LEGO1 0x100c31c0
MxRegion::MxRegion()
{
	m_list = new MxRegionList;
	m_rect.SetPoint(MxPoint32(INT_MAX, INT_MAX));
	m_rect.SetSize(MxSize32(-1, -1));
}

// OFFSET: LEGO1 0x100c3660
MxBool MxRegion::vtable20()
{
	return m_list->GetCount() == 0;
}

// OFFSET: LEGO1 0x100c3690
MxRegion::~MxRegion()
{
	if (m_list)
		delete m_list;
}

// OFFSET: LEGO1 0x100c3700
void MxRegion::Reset()
{
	m_list->DeleteAll();
	m_rect.SetPoint(MxPoint32(INT_MAX, INT_MAX));
	m_rect.SetSize(MxSize32(-1, -1));
}

// OFFSET: LEGO1 0x100c3750
void MxRegion::vtable18(MxRect32& p_rect)
{
	MxRect32 rectCopy(p_rect.GetPoint(), MxSize32(p_rect.m_right, p_rect.m_bottom));
	MxRegionListCursor cursor(m_list);

	if (rectCopy.m_left < rectCopy.m_right) {
		while (rectCopy.m_top < rectCopy.m_bottom) {
			MxRegionTopBottom* topBottom;
			if (!cursor.Next(topBottom))
				break;

			if (topBottom->m_top >= rectCopy.m_bottom) {
				cursor.Prepend(new MxRegionTopBottom(rectCopy));
				rectCopy.m_top = rectCopy.m_bottom;
			}
			else if (rectCopy.m_top < topBottom->m_bottom) {
				if (rectCopy.m_top < topBottom->m_top) {
					MxRect32 topBottomRect(rectCopy.GetPoint(), MxSize32(rectCopy.m_right, topBottom->m_top));

					cursor.Prepend(new MxRegionTopBottom(topBottomRect));
					rectCopy.m_top = topBottom->m_top;
				}
				else if (topBottom->m_top < rectCopy.m_top) {
					MxRegionTopBottom* newTopBottom = topBottom->Clone();
					newTopBottom->m_bottom = rectCopy.m_top;
					topBottom->m_top = rectCopy.m_top;
					cursor.Prepend(newTopBottom);
				}

				if (rectCopy.m_bottom < topBottom->m_bottom) {
					MxRegionTopBottom* newTopBottom = topBottom->Clone();
					newTopBottom->m_bottom = rectCopy.m_bottom;
					topBottom->m_top = rectCopy.m_bottom;
					newTopBottom->FUN_100c5280(rectCopy.m_left, rectCopy.m_right);
					// TODO: _InsertEntry currently inlined, shouldn't be
					cursor.Prepend(newTopBottom);
					rectCopy.m_top = rectCopy.m_bottom;
				}
				else {
					topBottom->FUN_100c5280(rectCopy.m_left, rectCopy.m_right);
					rectCopy.m_top = topBottom->m_bottom;
				}
			}

			if (rectCopy.m_right <= rectCopy.m_left)
				break;
		}
	}

	if (rectCopy.m_left < rectCopy.m_right && rectCopy.m_top < rectCopy.m_bottom) {
		MxRegionTopBottom* newTopBottom = new MxRegionTopBottom(rectCopy);
		m_list->OtherAppend(newTopBottom);
	}

	m_rect.m_left = m_rect.m_left <= p_rect.m_left ? m_rect.m_left : p_rect.m_left;
	m_rect.m_top = m_rect.m_top <= p_rect.m_top ? m_rect.m_top : p_rect.m_top;
	m_rect.m_right = m_rect.m_right <= p_rect.m_right ? p_rect.m_right : m_rect.m_right;
	m_rect.m_bottom = m_rect.m_bottom <= p_rect.m_bottom ? p_rect.m_bottom : m_rect.m_bottom;
}

// OFFSET: LEGO1 0x100c3e20
MxBool MxRegion::vtable1c(MxRect32& p_rect)
{
	if (m_rect.m_left >= p_rect.m_right || p_rect.m_left >= m_rect.m_right || m_rect.m_top >= p_rect.m_bottom ||
		p_rect.m_top >= m_rect.m_bottom)
		return FALSE;

	MxRegionListCursor cursor(m_list);
	MxRegionTopBottom* topBottom;

	while (cursor.Next(topBottom)) {
		MxS32 top = topBottom->m_top;
		if ((topBottom->m_top = top) >= p_rect.m_bottom)
			return FALSE;
		if (topBottom->m_bottom > p_rect.m_top && topBottom->FUN_100c57b0(p_rect))
			return TRUE;
	}

	return FALSE;
}

// OFFSET: LEGO1 0x100c4c90
MxRegionTopBottom::MxRegionTopBottom(MxS32 p_top, MxS32 p_bottom)
{
	m_top = p_top;
	m_bottom = p_bottom;
	m_leftRightList = new MxRegionLeftRightList;
}

// OFFSET: LEGO1 0x100c50e0
MxRegionTopBottom::MxRegionTopBottom(MxRect32& p_rect)
{
	m_top = p_rect.m_top;
	m_bottom = p_rect.m_bottom;
	m_leftRightList = new MxRegionLeftRightList;

	MxRegionLeftRight* leftRight = new MxRegionLeftRight(p_rect.m_left, p_rect.m_right);
	m_leftRightList->Append(leftRight);
}

// OFFSET: LEGO1 0x100c5280
void MxRegionTopBottom::FUN_100c5280(MxS32 p_left, MxS32 p_right)
{
	MxRegionLeftRightListCursor a(m_leftRightList);
	MxRegionLeftRightListCursor b(m_leftRightList);

	MxRegionLeftRight* leftRight;
	while (a.Next(leftRight) && leftRight->m_right < p_left)
		;

	if (!a.HasMatch()) {
		MxRegionLeftRight* copy = new MxRegionLeftRight(p_left, p_right);
		m_leftRightList->OtherAppend(copy);
	}
	else {
		if (p_left > leftRight->m_left)
			p_left = leftRight->m_left;

		while (leftRight->m_left < p_right) {
			if (p_right < leftRight->m_right)
				p_right = leftRight->m_right;

			// TODO: Currently inlined, shouldn't be
			b = a;
			b.Advance();

			if (a.HasMatch()) {
				a.Destroy();
				a.Detach();
			}

			if (!b.Current(leftRight))
				break;

			a = b;
		}

		if (a.HasMatch()) {
			MxRegionLeftRight* copy = new MxRegionLeftRight(p_left, p_right);
			a.Prepend(copy);
		}
		else {
			MxRegionLeftRight* copy = new MxRegionLeftRight(p_left, p_right);
			m_leftRightList->OtherAppend(copy);
		}
	}
}

// OFFSET: LEGO1 0x100c55d0
MxRegionTopBottom* MxRegionTopBottom::Clone()
{
	MxRegionTopBottom* clone = new MxRegionTopBottom(m_top, m_bottom);

	MxRegionLeftRightListCursor cursor(m_leftRightList);
	MxRegionLeftRight* leftRight;

	while (cursor.Next(leftRight))
		clone->m_leftRightList->Append(leftRight->Clone());

	return clone;
}

// OFFSET: LEGO1 0x100c57b0
MxBool MxRegionTopBottom::FUN_100c57b0(MxRect32& p_rect)
{
	MxRegionLeftRightListCursor cursor(m_leftRightList);
	MxRegionLeftRight* leftRight;

	while (cursor.Next(leftRight)) {
		if (p_rect.m_right <= leftRight->m_left)
			return FALSE;
		if (leftRight->m_right > p_rect.m_left)
			return TRUE;
	}

	return FALSE;
}
