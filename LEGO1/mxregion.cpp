#include "mxregion.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxRegion, 0x1c);
DECOMP_SIZE_ASSERT(MxRegionTopBottom, 0x0c);
DECOMP_SIZE_ASSERT(MxRegionLeftRight, 0x08);

// FUNCTION: LEGO1 0x100c31c0
MxRegion::MxRegion()
{
	m_list = new MxRegionTopBottomList;
	m_rect = MxRect32(INT_MAX, INT_MAX, -1, -1);
}

// FUNCTION: LEGO1 0x100c3660
MxBool MxRegion::VTable0x20()
{
	return m_list->GetCount() == 0;
}

// FUNCTION: LEGO1 0x100c3690
MxRegion::~MxRegion()
{
	if (m_list)
		delete m_list;
}

// FUNCTION: LEGO1 0x100c3700
void MxRegion::Reset()
{
	m_list->DeleteAll();
	m_rect = MxRect32(INT_MAX, INT_MAX, -1, -1);
}

// FUNCTION: LEGO1 0x100c3750
void MxRegion::VTable0x18(MxRect32& p_rect)
{
	MxRect32 rect(p_rect);
	MxRect32 newRect;
	MxRegionTopBottomListCursor cursor(m_list);
	MxRegionTopBottom* topBottom;

	while (rect.IsValid() && cursor.Next(topBottom)) {
		if (topBottom->GetTop() >= rect.GetBottom()) {
			MxRegionTopBottom* newTopBottom = new MxRegionTopBottom(rect);
			cursor.Prepend(newTopBottom);
			rect.SetTop(rect.GetBottom());
		}
		else if (rect.GetTop() < topBottom->GetBottom()) {
			if (rect.GetTop() < topBottom->GetTop()) {
				newRect = rect;
				newRect.SetBottom(topBottom->GetTop());
				MxRegionTopBottom* newTopBottom = new MxRegionTopBottom(newRect);
				cursor.Prepend(newTopBottom);
				rect.SetTop(topBottom->GetTop());
			}
			else if (topBottom->GetTop() < rect.GetTop()) {
				MxRegionTopBottom* newTopBottom = topBottom->Clone();
				newTopBottom->SetBottom(rect.GetTop());
				topBottom->SetTop(rect.GetTop());
				cursor.Prepend(newTopBottom);
			}

			if (rect.GetBottom() < topBottom->GetBottom()) {
				MxRegionTopBottom* newTopBottom = topBottom->Clone();
				newTopBottom->SetBottom(rect.GetBottom());
				topBottom->SetTop(rect.GetBottom());
				newTopBottom->FUN_100c5280(rect.GetLeft(), rect.GetRight());
				cursor.Prepend(newTopBottom);
				rect.SetTop(rect.GetBottom());
			}
			else {
				topBottom->FUN_100c5280(rect.GetLeft(), rect.GetRight());
				rect.SetTop(topBottom->GetBottom());
			}
		}
	}

	if (rect.IsValid()) {
		MxRegionTopBottom* newTopBottom = new MxRegionTopBottom(rect);
		m_list->Append(newTopBottom);
	}

	m_rect.UpdateBounds(p_rect);
}

// FUNCTION: LEGO1 0x100c3e20
MxBool MxRegion::VTable0x1c(MxRect32& p_rect)
{
	if (!m_rect.IntersectsWith(p_rect))
		return FALSE;

	MxRegionTopBottomListCursor cursor(m_list);
	MxRegionTopBottom* topBottom;

	while (cursor.Next(topBottom)) {
		if (topBottom->GetTop() >= p_rect.GetBottom())
			return FALSE;
		if (topBottom->GetBottom() > p_rect.GetTop() && topBottom->FUN_100c57b0(p_rect))
			return TRUE;
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100c4c90
MxRegionTopBottom::MxRegionTopBottom(MxS32 p_top, MxS32 p_bottom)
{
	m_top = p_top;
	m_bottom = p_bottom;
	m_leftRightList = new MxRegionLeftRightList;
}

// FUNCTION: LEGO1 0x100c50e0
MxRegionTopBottom::MxRegionTopBottom(MxRect32& p_rect)
{
	m_top = p_rect.GetTop();
	m_bottom = p_rect.GetBottom();
	m_leftRightList = new MxRegionLeftRightList;

	MxRegionLeftRight* leftRight = new MxRegionLeftRight(p_rect.GetLeft(), p_rect.GetRight());
	m_leftRightList->Append(leftRight);
}

// FUNCTION: LEGO1 0x100c5280
void MxRegionTopBottom::FUN_100c5280(MxS32 p_left, MxS32 p_right)
{
	MxRegionLeftRightListCursor a(m_leftRightList);
	MxRegionLeftRightListCursor b(m_leftRightList);

	MxRegionLeftRight* leftRight;
	while (a.Next(leftRight) && leftRight->GetRight() < p_left)
		;

	if (!a.HasMatch()) {
		MxRegionLeftRight* copy = new MxRegionLeftRight(p_left, p_right);
		m_leftRightList->Append(copy);
	}
	else {
		if (p_left > leftRight->GetLeft())
			p_left = leftRight->GetLeft();

		while (leftRight->GetLeft() < p_right) {
			if (p_right < leftRight->GetRight())
				p_right = leftRight->GetRight();

			b = a;
			b.Next();
			a.Destroy();

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
			m_leftRightList->Append(copy);
		}
	}
}

// FUNCTION: LEGO1 0x100c55d0
MxRegionTopBottom* MxRegionTopBottom::Clone()
{
	MxRegionTopBottom* clone = new MxRegionTopBottom(m_top, m_bottom);

	MxRegionLeftRightListCursor cursor(m_leftRightList);
	MxRegionLeftRight* leftRight;

	while (cursor.Next(leftRight))
		clone->m_leftRightList->Append(leftRight->Clone());

	return clone;
}

// FUNCTION: LEGO1 0x100c57b0
MxBool MxRegionTopBottom::FUN_100c57b0(MxRect32& p_rect)
{
	MxRegionLeftRightListCursor cursor(m_leftRightList);
	MxRegionLeftRight* leftRight;

	while (cursor.Next(leftRight)) {
		if (p_rect.GetRight() <= leftRight->GetLeft())
			return FALSE;
		if (leftRight->GetRight() > p_rect.GetLeft())
			return TRUE;
	}

	return FALSE;
}
