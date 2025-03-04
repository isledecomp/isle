#include "mxregion.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxRegion, 0x1c)
DECOMP_SIZE_ASSERT(MxSpan, 0x0c)
DECOMP_SIZE_ASSERT(MxSegment, 0x08)
DECOMP_SIZE_ASSERT(MxRegionCursor, 0x18)

// FUNCTION: LEGO1 0x100c31c0
// FUNCTION: BETA10 0x10148f00
MxRegion::MxRegion()
{
	m_spanList = new MxSpanList;
	m_boundingRect = MxRect32(INT_MAX, INT_MAX, -1, -1);
}

// FUNCTION: LEGO1 0x100c3690
// FUNCTION: BETA10 0x10148fe8
MxRegion::~MxRegion()
{
	delete m_spanList;
}

// FUNCTION: LEGO1 0x100c3700
// FUNCTION: BETA10 0x1014907a
void MxRegion::Reset()
{
	m_spanList->DeleteAll();
	m_boundingRect = MxRect32(INT_MAX, INT_MAX, -1, -1);
}

// FUNCTION: LEGO1 0x100c3750
// FUNCTION: BETA10 0x101490bd
void MxRegion::AddRect(MxRect32& p_rect)
{
	MxRect32 rect(p_rect);
	MxRect32 newRect;
	MxSpanListCursor cursor(m_spanList);
	MxSpan* span;

	while (!rect.Empty() && cursor.Next(span)) {
		if (span->GetMin() >= rect.GetBottom()) {
			MxSpan* newSpan = new MxSpan(rect);
			cursor.Prepend(newSpan);
			rect.SetTop(rect.GetBottom());
		}
		else if (rect.GetTop() < span->GetMax()) {
			if (rect.GetTop() < span->GetMin()) {
				newRect = rect;
				newRect.SetBottom(span->GetMin());
				MxSpan* newSpan = new MxSpan(newRect);
				cursor.Prepend(newSpan);
				rect.SetTop(span->GetMin());
			}
			else if (span->GetMin() < rect.GetTop()) {
				MxSpan* newSpan = span->Clone();
				newSpan->SetMax(rect.GetTop());
				span->SetMin(rect.GetTop());
				cursor.Prepend(newSpan);
			}

			if (rect.GetBottom() < span->GetMax()) {
				MxSpan* newSpan = span->Clone();
				newSpan->SetMax(rect.GetBottom());
				span->SetMin(rect.GetBottom());
				newSpan->AddSegment(rect.GetLeft(), rect.GetRight());
				cursor.Prepend(newSpan);
				rect.SetTop(rect.GetBottom());
			}
			else {
				span->AddSegment(rect.GetLeft(), rect.GetRight());
				rect.SetTop(span->GetMax());
			}
		}
	}

	if (!rect.Empty()) {
		MxSpan* newSpan = new MxSpan(rect);
		m_spanList->Append(newSpan);
	}

	m_boundingRect |= p_rect;
}

// FUNCTION: LEGO1 0x100c3e20
// FUNCTION: BETA10 0x10149535
MxBool MxRegion::Intersects(MxRect32& p_rect)
{
	if (!m_boundingRect.Intersects(p_rect)) {
		return FALSE;
	}

	MxSpanListCursor cursor(m_spanList);
	MxSpan* span;

	while (cursor.Next(span)) {
		if (span->GetMin() >= p_rect.GetBottom()) {
			return FALSE;
		}

		if (span->GetMax() > p_rect.GetTop() && span->IntersectsH(p_rect)) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100c3f70
// FUNCTION: BETA10 0x10149663
MxRegionCursor::MxRegionCursor(MxRegion* p_region)
{
	m_region = p_region;
	m_rect = NULL;
	m_spanListCursor = new MxSpanListCursor(m_region->m_spanList);
	m_segListCursor = NULL;
}

// FUNCTION: LEGO1 0x100c40b0
MxRegionCursor::~MxRegionCursor()
{
	if (m_rect) {
		delete m_rect;
	}

	if (m_spanListCursor) {
		delete m_spanListCursor;
	}

	if (m_segListCursor) {
		delete m_segListCursor;
	}
}

// FUNCTION: LEGO1 0x100c4140
MxRect32* MxRegionCursor::Head()
{
	m_spanListCursor->Head();

	MxSpan* span;
	if (m_spanListCursor->Current(span)) {
		CreateSegmentListCursor(span->m_segList);

		MxSegment* segment;
		m_segListCursor->First(segment);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
	}
	else {
		Reset();
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c41d0
MxRect32* MxRegionCursor::Tail()
{
	m_spanListCursor->Tail();

	MxSpan* span;
	if (m_spanListCursor->Current(span)) {
		CreateSegmentListCursor(span->m_segList);

		MxSegment* segment;
		m_segListCursor->Last(segment);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
	}
	else {
		Reset();
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c4260
MxRect32* MxRegionCursor::Next()
{
	MxSegment* segment;
	MxSpan* span;

	if (m_segListCursor && m_segListCursor->Next(segment)) {
		m_spanListCursor->Current(span);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
		return m_rect;
	}

	if (m_spanListCursor->Next(span)) {
		CreateSegmentListCursor(span->m_segList);
		m_segListCursor->First(segment);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
		return m_rect;
	}

	Reset();
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4360
MxRect32* MxRegionCursor::Prev()
{
	MxSegment* segment;
	MxSpan* span;

	if (m_segListCursor && m_segListCursor->Prev(segment)) {
		m_spanListCursor->Current(span);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
		return m_rect;
	}

	if (m_spanListCursor->Prev(span)) {
		CreateSegmentListCursor(span->m_segList);
		m_segListCursor->Last(segment);

		SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
		return m_rect;
	}

	Reset();
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4460
MxRect32* MxRegionCursor::Head(MxRect32& p_rect)
{
	m_spanListCursor->Reset();
	NextSpan(p_rect);
	return m_rect;
}

// FUNCTION: LEGO1 0x100c4480
MxRect32* MxRegionCursor::Tail(MxRect32& p_rect)
{
	m_spanListCursor->Reset();
	PrevSpan(p_rect);
	return m_rect;
}

// FUNCTION: LEGO1 0x100c44a0
MxRect32* MxRegionCursor::Next(MxRect32& p_rect)
{
	MxSegment* segment;

	if (m_segListCursor && m_segListCursor->Next(segment)) {
		MxSpan* span;

		m_spanListCursor->Current(span);

		if (span->IntersectsV(p_rect) && segment->IntersectsH(p_rect)) {
			SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
			*m_rect &= p_rect;
		}
		else {
			NextSpan(p_rect);
		}
	}
	else {
		NextSpan(p_rect);
	}

	return m_rect;
}

// FUNCTION: LEGO1 0x100c4590
MxRect32* MxRegionCursor::Prev(MxRect32& p_rect)
{
	MxSegment* segment;

	if (m_segListCursor && m_segListCursor->Prev(segment)) {
		MxSpan* span;

		m_spanListCursor->Current(span);

		if (span->IntersectsV(p_rect) && segment->IntersectsH(p_rect)) {
			SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
			*m_rect &= p_rect;
		}
		else {
			PrevSpan(p_rect);
		}
	}
	else {
		PrevSpan(p_rect);
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

	m_spanListCursor->Reset();

	if (m_segListCursor) {
		delete m_segListCursor;
		m_segListCursor = NULL;
	}
}

// FUNCTION: LEGO1 0x100c46c0
void MxRegionCursor::CreateSegmentListCursor(MxSegmentList* p_segList)
{
	if (m_segListCursor) {
		delete m_segListCursor;
	}

	m_segListCursor = new MxSegmentListCursor(p_segList);
}

// FUNCTION: LEGO1 0x100c4980
void MxRegionCursor::SetRect(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom)
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
void MxRegionCursor::NextSpan(MxRect32& p_rect)
{
	MxSpan* span;
	while (m_spanListCursor->Next(span)) {
		if (p_rect.GetBottom() <= span->GetMin()) {
			Reset();
			return;
		}

		if (p_rect.GetTop() < span->GetMax()) {
			CreateSegmentListCursor(span->m_segList);

			MxSegment* segment;
			while (m_segListCursor->Next(segment)) {
				if (p_rect.GetRight() <= segment->GetMin()) {
					break;
				}

				if (p_rect.GetLeft() < segment->GetMax()) {
					SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
					*m_rect &= p_rect;
					return;
				}
			}
		}
	}

	Reset();
}

// FUNCTION: LEGO1 0x100c4b50
void MxRegionCursor::PrevSpan(MxRect32& p_rect)
{
	MxSpan* span;
	while (m_spanListCursor->Prev(span)) {
		if (span->GetMax() <= p_rect.GetTop()) {
			Reset();
			return;
		}

		if (span->GetMin() < p_rect.GetBottom()) {
			CreateSegmentListCursor(span->m_segList);

			MxSegment* segment;
			while (m_segListCursor->Prev(segment)) {
				if (segment->GetMax() <= p_rect.GetLeft()) {
					break;
				}

				if (segment->GetMin() < p_rect.GetRight()) {
					SetRect(segment->GetMin(), span->GetMin(), segment->GetMax(), span->GetMax());
					*m_rect &= p_rect;
					return;
				}
			}
		}
	}

	Reset();
}

// FUNCTION: LEGO1 0x100c4c90
MxSpan::MxSpan(MxS32 p_min, MxS32 p_max)
{
	m_min = p_min;
	m_max = p_max;
	m_segList = new MxSegmentList;
}

// FUNCTION: LEGO1 0x100c50e0
// FUNCTION: BETA10 0x1014a2d6
MxSpan::MxSpan(MxRect32& p_rect)
{
	m_min = p_rect.GetTop();
	m_max = p_rect.GetBottom();
	m_segList = new MxSegmentList;

	MxSegment* segment = new MxSegment(p_rect.GetLeft(), p_rect.GetRight());
	m_segList->Append(segment);
}

// FUNCTION: LEGO1 0x100c5280
// FUNCTION: BETA10 0x1014a3fc
void MxSpan::AddSegment(MxS32 p_min, MxS32 p_max)
{
	MxSegmentListCursor a(m_segList);
	MxSegmentListCursor b(m_segList);

	MxSegment* segment;
	while (a.Next(segment) && segment->GetMax() < p_min) {
		;
	}

	if (a.HasMatch()) {
		if (p_min > segment->GetMin()) {
			p_min = segment->GetMin();
		}

		while (segment->GetMin() < p_max) {
			if (p_max < segment->GetMax()) {
				p_max = segment->GetMax();
			}

			b = a;
			b.Next();
			a.Destroy();

			if (!b.Current(segment)) {
				break;
			}

			a = b;
		}

		if (a.HasMatch()) {
			MxSegment* copy = new MxSegment(p_min, p_max);
			a.Prepend(copy);
		}
		else {
			MxSegment* copy = new MxSegment(p_min, p_max);
			m_segList->Append(copy);
		}
	}
	else {
		MxSegment* copy = new MxSegment(p_min, p_max);
		m_segList->Append(copy);
	}
}

// FUNCTION: LEGO1 0x100c55d0
MxSpan* MxSpan::Clone()
{
	MxSpan* clone = new MxSpan(m_min, m_max);

	MxSegmentListCursor cursor(m_segList);
	MxSegment* segment;

	while (cursor.Next(segment)) {
		clone->m_segList->Append(segment->Clone());
	}

	return clone;
}

// FUNCTION: LEGO1 0x100c57b0
// FUNCTION: BETA10 0x1014aa46
MxBool MxSpan::IntersectsH(MxRect32& p_rect)
{
	MxSegmentListCursor cursor(m_segList);
	MxSegment* segment;

	while (cursor.Next(segment)) {
		if (p_rect.GetRight() <= segment->GetMin()) {
			return FALSE;
		}

		if (segment->GetMax() > p_rect.GetLeft()) {
			return TRUE;
		}
	}

	return FALSE;
}
