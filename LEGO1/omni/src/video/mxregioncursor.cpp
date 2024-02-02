#include "mxregioncursor.h"

DECOMP_SIZE_ASSERT(MxRegionCursor, 0x18);

// FUNCTION: LEGO1 0x100c3f70
MxRegionCursor::MxRegionCursor(MxRegion* p_region)
{
	m_region = p_region;
	m_rect = NULL;
	m_topBottomCursor = new MxRegionTopBottomListCursor(m_region->m_list);
	m_leftRightCursor = NULL;
}

// FUNCTION: LEGO1 0x100c40b0
MxRegionCursor::~MxRegionCursor()
{
	if (m_rect) {
		delete m_rect;
	}

	if (m_topBottomCursor) {
		delete m_topBottomCursor;
	}

	if (m_leftRightCursor) {
		delete m_leftRightCursor;
	}
}

// FUNCTION: LEGO1 0x100c4140
MxRect32* MxRegionCursor::VTable0x18()
{
	m_topBottomCursor->Head();

	MxRegionTopBottom* topBottom;
	if (m_topBottomCursor->Current(topBottom)) {
		FUN_100c46c0(*topBottom->m_leftRightList);

		MxRegionLeftRight* leftRight;
		m_leftRightCursor->First(leftRight);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
	}
	else {
		Reset();
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c41d0
MxRect32* MxRegionCursor::VTable0x20()
{
	m_topBottomCursor->Tail();

	MxRegionTopBottom* topBottom;
	if (m_topBottomCursor->Current(topBottom)) {
		FUN_100c46c0(*topBottom->m_leftRightList);

		MxRegionLeftRight* leftRight;
		m_leftRightCursor->Last(leftRight);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
	}
	else {
		Reset();
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c4260
MxRect32* MxRegionCursor::VTable0x28()
{
	MxRegionLeftRight* leftRight;
	MxRegionTopBottom* topBottom;

	if (m_leftRightCursor && m_leftRightCursor->Next(leftRight)) {
		m_topBottomCursor->Current(topBottom);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
		return m_rect;
	}

	if (m_topBottomCursor->Next(topBottom)) {
		FUN_100c46c0(*topBottom->m_leftRightList);
		m_leftRightCursor->First(leftRight);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
		return m_rect;
	}

	Reset();
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4360
MxRect32* MxRegionCursor::VTable0x30()
{
	MxRegionLeftRight* leftRight;
	MxRegionTopBottom* topBottom;

	if (m_leftRightCursor && m_leftRightCursor->Prev(leftRight)) {
		m_topBottomCursor->Current(topBottom);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
		return m_rect;
	}

	if (m_topBottomCursor->Prev(topBottom)) {
		FUN_100c46c0(*topBottom->m_leftRightList);
		m_leftRightCursor->Last(leftRight);

		UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
		return m_rect;
	}

	Reset();
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4460
MxRect32* MxRegionCursor::VTable0x14(MxRect32& p_rect)
{
	m_topBottomCursor->Reset();
	FUN_100c4a20(p_rect);
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4480
MxRect32* MxRegionCursor::VTable0x1c(MxRect32& p_rect)
{
	m_topBottomCursor->Reset();
	FUN_100c4b50(p_rect);
	return m_rect;
}

// FUNCTION: LEGO1 0x100c44a0
MxRect32* MxRegionCursor::VTable0x24(MxRect32& p_rect)
{
	MxRegionLeftRight* leftRight;

	if (m_leftRightCursor && m_leftRightCursor->Next(leftRight)) {
		MxRegionTopBottom* topBottom;

		m_topBottomCursor->Current(topBottom);

		if (topBottom->IntersectsWith(p_rect) && leftRight->IntersectsWith(p_rect)) {
			UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
			m_rect->Intersect(p_rect);
		}
		else {
			FUN_100c4a20(p_rect);
		}
	}
	else {
		FUN_100c4a20(p_rect);
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c4590
MxRect32* MxRegionCursor::VTable0x2c(MxRect32& p_rect)
{
	MxRegionLeftRight* leftRight;

	if (m_leftRightCursor && m_leftRightCursor->Prev(leftRight)) {
		MxRegionTopBottom* topBottom;

		m_topBottomCursor->Current(topBottom);

		if (topBottom->IntersectsWith(p_rect) && leftRight->IntersectsWith(p_rect)) {
			UpdateRect(leftRight->GetLeft(), topBottom->GetTop(), leftRight->GetRight(), topBottom->GetBottom());
			m_rect->Intersect(p_rect);
		}
		else {
			FUN_100c4b50(p_rect);
		}
	}
	else {
		FUN_100c4b50(p_rect);
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c4680
void MxRegionCursor::Reset()
{
	if (m_rect) {
		delete m_rect;
		m_rect = NULL;
	}

	m_topBottomCursor->Reset();

	if (m_leftRightCursor) {
		delete m_leftRightCursor;
		m_leftRightCursor = NULL;
	}
}

// FUNCTION: LEGO1 0x100c46c0
void MxRegionCursor::FUN_100c46c0(MxRegionLeftRightList& p_leftRightList)
{
	if (m_leftRightCursor) {
		delete m_leftRightCursor;
	}

	m_leftRightCursor = new MxRegionLeftRightListCursor(&p_leftRightList);
}

// FUNCTION: LEGO1 0x100c4980
void MxRegionCursor::UpdateRect(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom)
{
	if (!m_rect) {
		m_rect = new MxRect32;
	}

	m_rect->SetLeft(p_left);
	m_rect->SetTop(p_top);
	m_rect->SetRight(p_right);
	m_rect->SetBottom(p_bottom);
}

// FUNCTION: LEGO1 0x100c4a20
void MxRegionCursor::FUN_100c4a20(MxRect32& p_rect)
{
	MxRegionTopBottom* topBottom;
	while (m_topBottomCursor->Next(topBottom)) {
		if (p_rect.GetBottom() <= topBottom->GetTop()) {
			Reset();
			return;
		}

		if (p_rect.GetTop() < topBottom->GetBottom()) {
			FUN_100c46c0(*topBottom->m_leftRightList);

			MxRegionLeftRight* leftRight;
			while (m_leftRightCursor->Next(leftRight)) {
				if (p_rect.GetRight() <= leftRight->GetLeft()) {
					break;
				}

				if (p_rect.GetLeft() < leftRight->GetRight()) {
					UpdateRect(
						leftRight->GetLeft(),
						topBottom->GetTop(),
						leftRight->GetRight(),
						topBottom->GetBottom()
					);
					m_rect->Intersect(p_rect);
					return;
				}
			}
		}
	}

	Reset();
}

// FUNCTION: LEGO1 0x100c4b50
void MxRegionCursor::FUN_100c4b50(MxRect32& p_rect)
{
	MxRegionTopBottom* topBottom;
	while (m_topBottomCursor->Prev(topBottom)) {
		if (topBottom->GetBottom() <= p_rect.GetTop()) {
			Reset();
			return;
		}

		if (topBottom->GetTop() < p_rect.GetBottom()) {
			FUN_100c46c0(*topBottom->m_leftRightList);

			MxRegionLeftRight* leftRight;
			while (m_leftRightCursor->Prev(leftRight)) {
				if (leftRight->GetRight() <= p_rect.GetLeft()) {
					break;
				}

				if (leftRight->GetLeft() < p_rect.GetRight()) {
					UpdateRect(
						leftRight->GetLeft(),
						topBottom->GetTop(),
						leftRight->GetRight(),
						topBottom->GetBottom()
					);
					m_rect->Intersect(p_rect);
					return;
				}
			}
		}
	}

	Reset();
}
