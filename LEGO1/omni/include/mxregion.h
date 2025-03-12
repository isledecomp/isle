#ifndef __MXREGION_H
#define __MXREGION_H

#include "decomp.h"
#include "mxcore.h"
#include "mxgeometry.h"
#include "mxlist.h"

// SIZE 0x08
class MxSegment {
protected:
	MxS32 m_min; // 0x00
	MxS32 m_max; // 0x04

public:
	// FUNCTION: BETA10 0x1014c360
	MxSegment(MxS32 p_min, MxS32 p_max)
	{
		m_min = p_min;
		m_max = p_max;
	}

	// FUNCTION: BETA10 0x1014b910
	MxS32 GetMin() { return m_min; }

	// FUNCTION: BETA10 0x1014b930
	MxS32 GetMax() { return m_max; }

	MxSegment* Clone() { return new MxSegment(m_min, m_max); }
	MxBool Combine(MxSegment& p_seg);
	MxBool Adjacent(MxSegment& p_seg) { return m_max == p_seg.m_min || m_min == p_seg.m_max; }
	MxBool IntersectsH(MxRect32& p_rect) { return p_rect.GetRight() > m_min && p_rect.GetTop() < m_max; }
	MxBool operator==(MxSegment& p_seg) { return m_min == p_seg.m_min && m_max == p_seg.m_max; }
	MxBool operator!=(MxSegment& p_seg) { return !operator==(p_seg); }
};

// VTABLE: LEGO1 0x100dcc40
// VTABLE: BETA10 0x101c2628
// class MxCollection<MxSegment *>

// VTABLE: LEGO1 0x100dcc58
// VTABLE: BETA10 0x101c2610
// class MxList<MxSegment *>

// VTABLE: LEGO1 0x100dcc70
// VTABLE: BETA10 0x101c25f8
// class MxPtrList<MxSegment>

// VTABLE: LEGO1 0x100dcc88
// VTABLE: BETA10 0x101c25e0
// SIZE 0x18
class MxSegmentList : public MxPtrList<MxSegment> {
public:
	// FUNCTION: BETA10 0x1014bdd0
	MxSegmentList() : MxPtrList<MxSegment>(TRUE) {}

	// SYNTHETIC: LEGO1 0x100c4e90
	// SYNTHETIC: BETA10 0x1014c1a0
	// MxSegmentList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcbf8
// VTABLE: BETA10 0x101c25b0
// class MxPtrListCursor<MxSegment>

// VTABLE: LEGO1 0x100dcc28
// VTABLE: BETA10 0x101c25c8
// class MxListCursor<MxSegment *>

// VTABLE: LEGO1 0x100dcc10
// VTABLE: BETA10 0x101c2598
class MxSegmentListCursor : public MxPtrListCursor<MxSegment> {
public:
	// FUNCTION: BETA10 0x1014ba10
	MxSegmentListCursor(MxSegmentList* p_list) : MxPtrListCursor<MxSegment>(p_list) {}
};

// SIZE 0x0c
class MxSpan {
protected:
	MxS32 m_min;              // 0x00
	MxS32 m_max;              // 0x04
	MxSegmentList* m_segList; // 0x08

public:
	MxSpan(MxS32 p_min, MxS32 p_max);
	MxSpan(MxRect32& p_rect);

	// FUNCTION: BETA10 0x1014b0f0
	~MxSpan() { delete m_segList; }

	// FUNCTION: BETA10 0x1014b3b0
	MxS32 GetMin() { return m_min; }

	void SetMin(MxS32 p_min) { m_min = p_min; }

	// FUNCTION: BETA10 0x1014b3f0
	MxS32 GetMax() { return m_max; }

	void SetMax(MxS32 p_max) { m_max = p_max; }
	MxSpan* Clone();
	void Compact();
	MxBool Combine(MxSpan& p_span);
	MxBool Adjacent(MxSpan& p_span) { return m_max == p_span.m_min || m_min == p_span.m_max; }
	MxBool HasSameSegments(MxSpan& p_span);
	MxBool IntersectsV(MxRect32& p_rect) { return p_rect.GetBottom() > m_min && p_rect.GetTop() < m_max; }
	MxBool IntersectsH(MxRect32& p_rect);
	void AddSegment(MxS32 p_min, MxS32 p_max);
	MxBool operator==(MxSpan& p_span)
	{
		return m_min == p_span.m_min && m_max == p_span.m_max && HasSameSegments(p_span);
	}
	MxBool operator!=(MxSpan& p_span) { return !operator==(p_span); }
	friend class MxRegionCursor;

	// SYNTHETIC: BETA10 0x1014b0b0
	// MxSpan::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcb10
// VTABLE: BETA10 0x101c24f8
// class MxCollection<MxSpan *>

// VTABLE: LEGO1 0x100dcb28
// VTABLE: BETA10 0x101c24e0
// class MxList<MxSpan *>

// VTABLE: LEGO1 0x100dcb40
// VTABLE: BETA10 0x101c24c8
// class MxPtrList<MxSpan>

// VTABLE: LEGO1 0x100dcb58
// VTABLE: BETA10 0x101c24b0
// SIZE 0x18
class MxSpanList : public MxPtrList<MxSpan> {
public:
	// FUNCTION: BETA10 0x1014abb0
	MxSpanList() : MxPtrList<MxSpan>(TRUE) {}

	// SYNTHETIC: LEGO1 0x100c3410
	// SYNTHETIC: BETA10 0x1014af90
	// MxSpanList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcb70
// VTABLE: BETA10 0x101c2528
// class MxPtrListCursor<MxSpan>

// VTABLE: LEGO1 0x100dcba0
// VTABLE: BETA10 0x101c2540
// class MxListCursor<MxSpan *>

// TODO: The initialize list param type should be MxSpanList, but doing that
// drastically reduced the match percentage for MxRegion::AddRect.
// (developer provided MxRegion.h file also uses MxSpanList*.)
// It also works with MxPtrList, so we'll do that until we figure this out.

// VTABLE: LEGO1 0x100dcb88
// VTABLE: BETA10 0x101c2510
class MxSpanListCursor : public MxPtrListCursor<MxSpan> {
public:
	// FUNCTION: BETA10 0x1014b470
	MxSpanListCursor(MxPtrList<MxSpan>* p_list) : MxPtrListCursor<MxSpan>(p_list) {}
};

// VTABLE: LEGO1 0x100dcae8
// SIZE 0x1c
class MxRegion : public MxCore {
protected:
	MxSpanList* m_spanList;  // 0x08
	MxRect32 m_boundingRect; // 0x0c

public:
	MxRegion();
	~MxRegion() override;
	MxRect32& GetBoundingRect() { return m_boundingRect; }
	virtual void Reset();                        // vtable+0x14
	virtual void AddRect(MxRect32& p_rect);      // vtable+0x18
	virtual MxBool Intersects(MxRect32& p_rect); // vtable+0x1c

	// FUNCTION: LEGO1 0x100c3660
	// FUNCTION: BETA10 0x1014b1d0
	virtual MxBool IsEmpty() { return m_spanList->GetNumElements() == 0; } // vtable+0x20

	void Compact();
	friend class MxRegionCursor;

	// SYNTHETIC: LEGO1 0x100c3670
	// SYNTHETIC: BETA10 0x1014b230
	// MxRegion::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcbb8
// SIZE 0x18
class MxRegionCursor : public MxCore {
protected:
	MxRegion* m_region;                   // 0x08
	MxRect32* m_rect;                     // 0x0c
	MxSpanListCursor* m_spanListCursor;   // 0x10
	MxSegmentListCursor* m_segListCursor; // 0x14
	void CreateSegmentListCursor(MxSegmentList* p_segList);
	void SetRect(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom);
	void NextSpan(MxRect32& p_rect);
	void PrevSpan(MxRect32& p_rect);

public:
	MxRegionCursor(MxRegion* p_region);
	~MxRegionCursor() override;
	virtual MxRect32* Head();                 // vtable+0x18
	virtual MxRect32* Tail();                 // vtable+0x20
	virtual MxRect32* Next();                 // vtable+0x28
	virtual MxRect32* Prev();                 // vtable+0x30
	virtual MxRect32* Head(MxRect32& p_rect); // vtable+0x14
	virtual MxRect32* Tail(MxRect32& p_rect); // vtable+0x1c
	virtual MxRect32* Next(MxRect32& p_rect); // vtable+0x24
	virtual MxRect32* Prev(MxRect32& p_rect); // vtable+0x2c

	// FUNCTION: LEGO1 0x100c4070
	virtual MxRect32* GetRect() { return m_rect; } // vtable+0x34

	// FUNCTION: LEGO1 0x100c4080
	virtual MxBool Valid() { return m_rect != NULL; } // vtable+0x38

	virtual void Reset(); // vtable+0x3c

	// SYNTHETIC: LEGO1 0x100c4090
	// MxRegionCursor::`scalar deleting destructor'
};

#ifdef REGION_SANITY_CHECK

class MxRectIntersection {
protected:
	MxRect32 m_rect;
	MxS32 m_numRects;

public:
	MxRect32& GetRect() { return m_rect; }
	void SetRect(MxRect32& p_rect) { m_rect = p_rect; }
	MxS32 GetNumRects() { return m_numRects; }
	void SetNumRects(MxS32 p_numRects) { m_numRects = p_numRects; }
};

class MxRectIntersectionList : public MxPtrList<MxRectIntersection> {
public:
	MxRectIntersectionList() : MxPtrList<MxRectIntersection>(TRUE) {}
};

class MxRectIntersectionListCursor : public MxPtrListCursor<MxRectIntersection> {
public:
	MxRectIntersectionListCursor(MxRectIntersectionList* p_list) : MxPtrListCursor<MxRectIntersection>(p_list) {}
};

class MxRegionSanityCheck {
protected:
	MxRectIntersectionList* m_rectIntersectionList;

public:
	MxRegionSanityCheck();
	~MxRegionSanityCheck();
	void Reset() { m_rectIntersectionList->Delete(); }
	void AddRect(MxRect32& p_rect);
	MxS32 CalculateArea();
};

#endif

// TEMPLATE: LEGO1 0x100c32e0
// TEMPLATE: BETA10 0x1014ac30
// MxCollection<MxSpan *>::Compare

// TEMPLATE: LEGO1 0x100c32f0
// TEMPLATE: BETA10 0x1014adf0
// MxCollection<MxSpan *>::~MxCollection<MxSpan *>

// TEMPLATE: LEGO1 0x100c3340
// TEMPLATE: BETA10 0x1014ae90
// MxCollection<MxSpan *>::Destroy

// TEMPLATE: LEGO1 0x100c3350
// TEMPLATE: BETA10 0x1014aea0
// MxList<MxSpan *>::~MxList<MxSpan *>

// TEMPLATE: LEGO1 0x100c33e0
// TEMPLATE: BETA10 0x1014af50
// MxPtrList<MxSpan>::Destroy

// TEMPLATE: LEGO1 0x100c3480
// TEMPLATE: BETA10 0x1014afd0
// MxPtrList<MxSpan>::~MxPtrList<MxSpan>

// SYNTHETIC: LEGO1 0x100c34d0
// SYNTHETIC: BETA10 0x1014b030
// MxCollection<MxSpan *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3540
// SYNTHETIC: BETA10 0x1014b070
// MxList<MxSpan *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c35f0
// SYNTHETIC: BETA10 0x1014b130
// MxPtrList<MxSpan>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3be0
// SYNTHETIC: BETA10 0x1014b600
// MxSpanListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c3c50
// TEMPLATE: BETA10 0x1014b640
// MxPtrListCursor<MxSpan>::~MxPtrListCursor<MxSpan>

// SYNTHETIC: LEGO1 0x100c3ca0
// SYNTHETIC: BETA10 0x1014b6a0
// MxListCursor<MxSpan *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3d10
// SYNTHETIC: BETA10 0x1014b6e0
// MxPtrListCursor<MxSpan>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c3d80
// TEMPLATE: BETA10 0x1014b720
// MxListCursor<MxSpan *>::~MxListCursor<MxSpan *>

// FUNCTION: LEGO1 0x100c3dd0
// FUNCTION: BETA10 0x1014b780
// MxSpanListCursor::~MxSpanListCursor

// SYNTHETIC: LEGO1 0x100c4790
// SYNTHETIC: BETA10 0x1014bba0
// MxSegmentListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4800
// TEMPLATE: BETA10 0x1014bbe0
// MxPtrListCursor<MxSegment>::~MxPtrListCursor<MxSegment>

// SYNTHETIC: LEGO1 0x100c4850
// SYNTHETIC: BETA10 0x1014bc40
// MxListCursor<MxSegment *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c48c0
// SYNTHETIC: BETA10 0x1014bc80
// MxPtrListCursor<MxSegment>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4930
// TEMPLATE: BETA10 0x1014bcc0
// MxListCursor<MxSegment *>::~MxListCursor<MxSegment *>

// TEMPLATE: LEGO1 0x100c4d80
// TEMPLATE: BETA10 0x1014be50
// MxCollection<MxSegment *>::Compare

// TEMPLATE: LEGO1 0x100c4d90
// TEMPLATE: BETA10 0x1014c010
// MxCollection<MxSegment *>::~MxCollection<MxSegment *>

// TEMPLATE: LEGO1 0x100c4de0
// TEMPLATE: BETA10 0x1014c0b0
// MxCollection<MxSegment *>::Destroy

// TEMPLATE: LEGO1 0x100c4df0
// TEMPLATE: BETA10 0x1014c0c0
// MxList<MxSegment *>::~MxList<MxSegment *>

// TEMPLATE: LEGO1 0x100c4f00
// TEMPLATE: BETA10 0x1014c1e0
// MxPtrList<MxSegment>::~MxPtrList<MxSegment>

// SYNTHETIC: LEGO1 0x100c4f50
// SYNTHETIC: BETA10 0x1014c240
// MxCollection<MxSegment *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4e80
// TEMPLATE: BETA10 0x1014c170
// MxPtrList<MxSegment>::Destroy

// SYNTHETIC: LEGO1 0x100c4fc0
// SYNTHETIC: BETA10 0x1014c280
// MxList<MxSegment *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c5070
// SYNTHETIC: BETA10 0x1014c2c0
// MxPtrList<MxSegment>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c54f0
// MxListCursor<MxSegment *>::MxListCursor<MxSegment *>

// FUNCTION: LEGO1 0x100c5560
// MxSegmentListCursor::~MxSegmentListCursor

// TEMPLATE: LEGO1 0x100c55b0
// MxListCursor<MxSegment *>::operator=

// TEMPLATE: LEGO1 0x100c58c0
// TEMPLATE: BETA10 0x1014c650
// MxList<MxSegment *>::InsertEntry

// TEMPLATE: LEGO1 0x100c5970
// TEMPLATE: BETA10 0x1014cb20
// MxList<MxSpan *>::InsertEntry

// TEMPLATE: LEGO1 0x100c5a20
// TEMPLATE: BETA10 0x1014d050
// MxListEntry<MxSpan *>::MxListEntry<MxSpan *>

// TEMPLATE: LEGO1 0x100c5a40
// TEMPLATE: BETA10 0x1014d150
// MxList<MxSegment *>::DeleteEntry

// TEMPLATE: BETA10 0x1014ac50
// MxPtrList<MxSpan>::MxPtrList<MxSpan>

// TEMPLATE: BETA10 0x1014acd0
// MxList<MxSpan *>::MxList<MxSpan *>

// TEMPLATE: BETA10 0x1014ad60
// MxCollection<MxSpan *>::MxCollection<MxSpan *>

// TEMPLATE: BETA10 0x1014ae60
// MxCollection<MxSpan *>::SetDestroy

// TEMPLATE: BETA10 0x1014af10
// MxPtrList<MxSpan>::SetOwnership

// FUNCTION: BETA10 0x1014b170
// MxSpanList::~MxSpanList

// TEMPLATE: BETA10 0x1014b440
// MxList<MxSpan *>::Append

// TEMPLATE: BETA10 0x1014b4f0
// MxPtrListCursor<MxSpan>::MxPtrListCursor<MxSpan>

// TEMPLATE: BETA10 0x1014b570
// MxListCursor<MxSpan *>::MxListCursor<MxSpan *>

// TEMPLATE: BETA10 0x1014ba90
// MxPtrListCursor<MxSegment>::MxPtrListCursor<MxSegment>

// TEMPLATE: BETA10 0x1014bb10
// MxListCursor<MxSegment *>::MxListCursor<MxSegment *>

// FUNCTION: BETA10 0x1014bd20
// MxSegmentListCursor::~MxSegmentListCursor

// TEMPLATE: BETA10 0x1014be70
// MxPtrList<MxSegment>::MxPtrList<MxSegment>

// TEMPLATE: BETA10 0x1014bef0
// MxList<MxSegment *>::MxList<MxSegment *>

// TEMPLATE: BETA10 0x1014bf80
// MxCollection<MxSegment *>::MxCollection<MxSegment *>

// TEMPLATE: BETA10 0x1014c080
// MxCollection<MxSegment *>::SetDestroy

// TEMPLATE: BETA10 0x1014c130
// MxPtrList<MxSegment>::SetOwnership

// FUNCTION: BETA10 0x1014c300
// MxSegmentList::~MxSegmentList

// TEMPLATE: BETA10 0x1014c390
// MxList<MxSegment *>::Append

// SYNTHETIC: BETA10 0x1014c3c0
// MxSegmentListCursor::operator=

// SYNTHETIC: BETA10 0x1014c3f0
// MxPtrListCursor<MxSegment>::operator=

// SYNTHETIC: BETA10 0x1014c420
// MxListCursor<MxSegment *>::operator=

// TEMPLATE: BETA10 0x1014c740
// MxList<MxSegment *>::DeleteAll

// TEMPLATE: BETA10 0x1014c7d0
// MxListCursor<MxSegment *>::First

// TEMPLATE: BETA10 0x1014c830
// MxListCursor<MxSegment *>::Last

// TEMPLATE: BETA10 0x1014c890
// MxListCursor<MxSegment *>::Next

// TEMPLATE: BETA10 0x1014c970
// MxListCursor<MxSegment *>::Prev

// TEMPLATE: BETA10 0x1014c9f0
// MxListCursor<MxSegment *>::Current

// TEMPLATE: BETA10 0x1014ca40
// MxListCursor<MxSegment *>::Prepend

// TEMPLATE: BETA10 0x1014ca90
// MxListCursor<MxSegment *>::Destroy

// TEMPLATE: BETA10 0x1014caf0
// MxListCursor<MxSegment *>::HasMatch

// TEMPLATE: BETA10 0x1014cc10
// MxList<MxSpan *>::DeleteAll

// TEMPLATE: BETA10 0x1014cd20
// MxListCursor<MxSpan *>::Next

// TEMPLATE: BETA10 0x1014cda0
// MxListCursor<MxSpan *>::Prev

// TEMPLATE: BETA10 0x1014ce70
// MxListCursor<MxSpan *>::Prepend

// TEMPLATE: BETA10 0x1014cec0
// MxListCursor<MxSpan *>::Destroy

// TEMPLATE: BETA10 0x1014cf50
// MxListEntry<MxSegment *>::MxListEntry<MxSegment *>

// TEMPLATE: BETA10 0x1014cf90
// MxListEntry<MxSegment *>::GetPrev

// TEMPLATE: BETA10 0x1014cfb0
// MxListEntry<MxSegment *>::SetPrev

// TEMPLATE: BETA10 0x1014cfe0
// MxListEntry<MxSegment *>::GetNext

// TEMPLATE: BETA10 0x1014d000
// MxListEntry<MxSegment *>::SetNext

// TEMPLATE: BETA10 0x1014d030
// MxListEntry<MxSegment *>::GetValue

// TEMPLATE: BETA10 0x1014d090
// MxListEntry<MxSpan *>::GetPrev

// TEMPLATE: BETA10 0x1014d0b0
// MxListEntry<MxSpan *>::SetPrev

// TEMPLATE: BETA10 0x1014d0e0
// MxListEntry<MxSpan *>::GetNext

// TEMPLATE: BETA10 0x1014d100
// MxListEntry<MxSpan *>::SetNext

// TEMPLATE: BETA10 0x1014d130
// MxListEntry<MxSpan *>::GetValue

// TEMPLATE: BETA10 0x1014d200
// MxList<MxSpan *>::DeleteEntry

// TEMPLATE: BETA10 0x1014b210
// MxList<MxSpan *>::GetNumElements

// TEMPLATE: BETA10 0x1014c910
// ?Next@?$MxListCursor@PAVMxSegment@@@@QAEEXZ

#endif // __MXREGION_H
