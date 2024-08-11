#ifndef MXREGIONLIST_H
#define MXREGIONLIST_H

#include "mxlist.h"

// SIZE 0x08
struct MxRegionLeftRight {
	MxRegionLeftRight(MxS32 p_left, MxS32 p_right)
	{
		m_left = p_left;
		m_right = p_right;
	}

	MxRegionLeftRight* Clone() { return new MxRegionLeftRight(m_left, m_right); }

	MxS32 GetLeft() { return m_left; }
	MxS32 GetRight() { return m_right; }

	void SetLeft(MxS32 p_left) { m_left = p_left; }
	void SetRight(MxS32 p_right) { m_right = p_right; }

	MxBool IntersectsWith(MxRect32& p_rect) { return m_left < p_rect.GetRight() && p_rect.GetTop() < m_right; }

private:
	MxS32 m_left;  // 0x00
	MxS32 m_right; // 0x04
};

// VTABLE: LEGO1 0x100dcc40
// VTABLE: BETA10 0x101c2628
// class MxCollection<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc58
// VTABLE: BETA10 0x101c2610
// class MxList<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc70
// VTABLE: BETA10 0x101c25f8
// class MxPtrList<MxRegionLeftRight>

// VTABLE: LEGO1 0x100dcc88
// VTABLE: BETA10 0x101c25e0
// SIZE 0x18
class MxRegionLeftRightList : public MxPtrList<MxRegionLeftRight> {
public:
	// FUNCTION: BETA10 0x1014bdd0
	MxRegionLeftRightList() : MxPtrList<MxRegionLeftRight>(TRUE) {}

	// SYNTHETIC: LEGO1 0x100c4e90
	// SYNTHETIC: BETA10 0x1014c1a0
	// MxRegionLeftRightList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcbf8
// VTABLE: BETA10 0x101c25b0
// class MxPtrListCursor<MxRegionLeftRight>

// VTABLE: LEGO1 0x100dcc28
// VTABLE: BETA10 0x101c25c8
// class MxListCursor<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc10
// VTABLE: BETA10 0x101c2598
class MxRegionLeftRightListCursor : public MxPtrListCursor<MxRegionLeftRight> {
public:
	// FUNCTION: BETA10 0x1014ba10
	MxRegionLeftRightListCursor(MxRegionLeftRightList* p_list) : MxPtrListCursor<MxRegionLeftRight>(p_list) {}
};

// SIZE 0x0c
struct MxRegionTopBottom {
	MxRegionTopBottom(MxRect32& p_rect);
	MxRegionTopBottom(MxS32 p_top, MxS32 p_bottom);
	~MxRegionTopBottom() { delete m_leftRightList; }

	MxRegionTopBottom* Clone();
	void MergeOrExpandRegions(MxS32 p_left, MxS32 p_right);
	MxBool CheckHorizontalOverlap(MxRect32& p_rect);

	MxS32 GetTop() { return m_top; }
	MxS32 GetBottom() { return m_bottom; }

	void SetTop(MxS32 p_top) { m_top = p_top; }
	void SetBottom(MxS32 p_bottom) { m_bottom = p_bottom; }

	MxBool IntersectsWith(MxRect32& p_rect) { return m_top < p_rect.GetBottom() && p_rect.GetTop() < m_bottom; }

	friend class MxRegionTopBottomList;
	friend class MxRegionCursor;

private:
	MxS32 m_top;                            // 0x00
	MxS32 m_bottom;                         // 0x04
	MxRegionLeftRightList* m_leftRightList; // 0x08
};

// VTABLE: LEGO1 0x100dcb10
// VTABLE: BETA10 0x101c24f8
// class MxCollection<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb28
// VTABLE: BETA10 0x101c24e0
// class MxList<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb40
// VTABLE: BETA10 0x101c24c8
// class MxPtrList<MxRegionTopBottom>

// VTABLE: LEGO1 0x100dcb58
// VTABLE: BETA10 0x101c24b0
// SIZE 0x18
class MxRegionTopBottomList : public MxPtrList<MxRegionTopBottom> {
public:
	// FUNCTION: BETA10 0x1014abb0
	MxRegionTopBottomList() : MxPtrList<MxRegionTopBottom>(TRUE) {}

	// SYNTHETIC: LEGO1 0x100c3410
	// SYNTHETIC: BETA10 0x1014af90
	// MxRegionTopBottomList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dcb70
// VTABLE: BETA10 0x101c2528
// class MxPtrListCursor<MxRegionTopBottom>

// VTABLE: LEGO1 0x100dcba0
// VTABLE: BETA10 0x101c2540
// class MxListCursor<MxRegionTopBottom *>

// TODO: The initialize list param type should be MxRegionTopBottomList, but doing that
// drastically reduced the match percentage for MxRegion::VTable0x18.
// It also works with MxPtrList, so we'll do that until we figure this out.

// VTABLE: LEGO1 0x100dcb88
// VTABLE: BETA10 0x101c2510
class MxRegionTopBottomListCursor : public MxPtrListCursor<MxRegionTopBottom> {
public:
	// FUNCTION: BETA10 0x1014b470
	MxRegionTopBottomListCursor(MxPtrList<MxRegionTopBottom>* p_list) : MxPtrListCursor<MxRegionTopBottom>(p_list) {}
};

// TEMPLATE: LEGO1 0x100c32e0
// TEMPLATE: BETA10 0x1014ac30
// MxCollection<MxRegionTopBottom *>::Compare

// TEMPLATE: LEGO1 0x100c32f0
// TEMPLATE: BETA10 0x1014adf0
// MxCollection<MxRegionTopBottom *>::~MxCollection<MxRegionTopBottom *>

// TEMPLATE: LEGO1 0x100c3340
// TEMPLATE: BETA10 0x1014ae90
// MxCollection<MxRegionTopBottom *>::Destroy

// TEMPLATE: LEGO1 0x100c3350
// TEMPLATE: BETA10 0x1014aea0
// MxList<MxRegionTopBottom *>::~MxList<MxRegionTopBottom *>

// TEMPLATE: LEGO1 0x100c33e0
// TEMPLATE: BETA10 0x1014af50
// MxPtrList<MxRegionTopBottom>::Destroy

// TEMPLATE: LEGO1 0x100c3480
// TEMPLATE: BETA10 0x1014afd0
// MxPtrList<MxRegionTopBottom>::~MxPtrList<MxRegionTopBottom>

// SYNTHETIC: LEGO1 0x100c34d0
// SYNTHETIC: BETA10 0x1014b030
// MxCollection<MxRegionTopBottom *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3540
// SYNTHETIC: BETA10 0x1014b070
// MxList<MxRegionTopBottom *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c35f0
// SYNTHETIC: BETA10 0x1014b130
// MxPtrList<MxRegionTopBottom>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3be0
// SYNTHETIC: BETA10 0x1014b600
// MxRegionTopBottomListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c3c50
// TEMPLATE: BETA10 0x1014b640
// MxPtrListCursor<MxRegionTopBottom>::~MxPtrListCursor<MxRegionTopBottom>

// SYNTHETIC: LEGO1 0x100c3ca0
// SYNTHETIC: BETA10 0x1014b6a0
// MxListCursor<MxRegionTopBottom *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c3d10
// SYNTHETIC: BETA10 0x1014b6e0
// MxPtrListCursor<MxRegionTopBottom>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c3d80
// TEMPLATE: BETA10 0x1014b720
// MxListCursor<MxRegionTopBottom *>::~MxListCursor<MxRegionTopBottom *>

// FUNCTION: LEGO1 0x100c3dd0
// FUNCTION: BETA10 0x1014b780
// MxRegionTopBottomListCursor::~MxRegionTopBottomListCursor

// SYNTHETIC: LEGO1 0x100c4790
// SYNTHETIC: BETA10 0x1014bba0
// MxRegionLeftRightListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4800
// TEMPLATE: BETA10 0x1014bbe0
// MxPtrListCursor<MxRegionLeftRight>::~MxPtrListCursor<MxRegionLeftRight>

// SYNTHETIC: LEGO1 0x100c4850
// SYNTHETIC: BETA10 0x1014bc40
// MxListCursor<MxRegionLeftRight *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c48c0
// SYNTHETIC: BETA10 0x1014bc80
// MxPtrListCursor<MxRegionLeftRight>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4930
// TEMPLATE: BETA10 0x1014bcc0
// MxListCursor<MxRegionLeftRight *>::~MxListCursor<MxRegionLeftRight *>

// TEMPLATE: LEGO1 0x100c4d80
// TEMPLATE: BETA10 0x1014be50
// MxCollection<MxRegionLeftRight *>::Compare

// TEMPLATE: LEGO1 0x100c4d90
// TEMPLATE: BETA10 0x1014c010
// MxCollection<MxRegionLeftRight *>::~MxCollection<MxRegionLeftRight *>

// TEMPLATE: LEGO1 0x100c4de0
// TEMPLATE: BETA10 0x1014c0b0
// MxCollection<MxRegionLeftRight *>::Destroy

// TEMPLATE: LEGO1 0x100c4df0
// TEMPLATE: BETA10 0x1014c0c0
// MxList<MxRegionLeftRight *>::~MxList<MxRegionLeftRight *>

// TEMPLATE: LEGO1 0x100c4f00
// TEMPLATE: BETA10 0x1014c1e0
// MxPtrList<MxRegionLeftRight>::~MxPtrList<MxRegionLeftRight>

// SYNTHETIC: LEGO1 0x100c4f50
// SYNTHETIC: BETA10 0x1014c240
// MxCollection<MxRegionLeftRight *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c4e80
// TEMPLATE: BETA10 0x1014c170
// MxPtrList<MxRegionLeftRight>::Destroy

// SYNTHETIC: LEGO1 0x100c4fc0
// SYNTHETIC: BETA10 0x1014c280
// MxList<MxRegionLeftRight *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c5070
// SYNTHETIC: BETA10 0x1014c2c0
// MxPtrList<MxRegionLeftRight>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100c54f0
// MxListCursor<MxRegionLeftRight *>::MxListCursor<MxRegionLeftRight *>

// FUNCTION: LEGO1 0x100c5560
// MxRegionLeftRightListCursor::~MxRegionLeftRightListCursor

// TEMPLATE: LEGO1 0x100c55b0
// MxListCursor<MxRegionLeftRight *>::operator=

// TEMPLATE: LEGO1 0x100c58c0
// TEMPLATE: BETA10 0x1014c650
// MxList<MxRegionLeftRight *>::InsertEntry

// TEMPLATE: LEGO1 0x100c5970
// TEMPLATE: BETA10 0x1014cb20
// MxList<MxRegionTopBottom *>::InsertEntry

// TEMPLATE: LEGO1 0x100c5a20
// TEMPLATE: BETA10 0x1014d050
// MxListEntry<MxRegionTopBottom *>::MxListEntry<MxRegionTopBottom *>

// TEMPLATE: LEGO1 0x100c5a40
// TEMPLATE: BETA10 0x1014d150
// MxList<MxRegionLeftRight *>::DeleteEntry

// TEMPLATE: BETA10 0x1014ac50
// MxPtrList<MxRegionTopBottom>::MxPtrList<MxRegionTopBottom>

// TEMPLATE: BETA10 0x1014acd0
// MxList<MxRegionTopBottom *>::MxList<MxRegionTopBottom *>

// TEMPLATE: BETA10 0x1014ad60
// MxCollection<MxRegionTopBottom *>::MxCollection<MxRegionTopBottom *>

// TEMPLATE: BETA10 0x1014ae60
// MxCollection<MxRegionTopBottom *>::SetDestroy

// TEMPLATE: BETA10 0x1014af10
// MxPtrList<MxRegionTopBottom>::SetOwnership

// FUNCTION: BETA10 0x1014b170
// MxRegionTopBottomList::~MxRegionTopBottomList

// TEMPLATE: BETA10 0x1014b440
// MxList<MxRegionTopBottom *>::Append

// TEMPLATE: BETA10 0x1014b4f0
// MxPtrListCursor<MxRegionTopBottom>::MxPtrListCursor<MxRegionTopBottom>

// TEMPLATE: BETA10 0x1014b570
// MxListCursor<MxRegionTopBottom *>::MxListCursor<MxRegionTopBottom *>

// TEMPLATE: BETA10 0x1014ba90
// MxPtrListCursor<MxRegionLeftRight>::MxPtrListCursor<MxRegionLeftRight>

// TEMPLATE: BETA10 0x1014bb10
// MxListCursor<MxRegionLeftRight *>::MxListCursor<MxRegionLeftRight *>

// FUNCTION: BETA10 0x1014bd20
// MxRegionLeftRightListCursor::~MxRegionLeftRightListCursor

// TEMPLATE: BETA10 0x1014be70
// MxPtrList<MxRegionLeftRight>::MxPtrList<MxRegionLeftRight>

// TEMPLATE: BETA10 0x1014bef0
// MxList<MxRegionLeftRight *>::MxList<MxRegionLeftRight *>

// TEMPLATE: BETA10 0x1014bf80
// MxCollection<MxRegionLeftRight *>::MxCollection<MxRegionLeftRight *>

// TEMPLATE: BETA10 0x1014c080
// MxCollection<MxRegionLeftRight *>::SetDestroy

// TEMPLATE: BETA10 0x1014c130
// MxPtrList<MxRegionLeftRight>::SetOwnership

// FUNCTION: BETA10 0x1014c300
// MxRegionLeftRightList::~MxRegionLeftRightList

// TEMPLATE: BETA10 0x1014c390
// MxList<MxRegionLeftRight *>::Append

// SYNTHETIC: BETA10 0x1014c3c0
// MxRegionLeftRightListCursor::operator=

// SYNTHETIC: BETA10 0x1014c3f0
// MxPtrListCursor<MxRegionLeftRight>::operator=

// SYNTHETIC: BETA10 0x1014c420
// MxListCursor<MxRegionLeftRight *>::operator=

// TEMPLATE: BETA10 0x1014c740
// MxList<MxRegionLeftRight *>::DeleteAll

// TEMPLATE: BETA10 0x1014c7d0
// MxListCursor<MxRegionLeftRight *>::First

// TEMPLATE: BETA10 0x1014c830
// MxListCursor<MxRegionLeftRight *>::Last

// TEMPLATE: BETA10 0x1014c890
// MxListCursor<MxRegionLeftRight *>::Next

// TEMPLATE: BETA10 0x1014c970
// MxListCursor<MxRegionLeftRight *>::Prev

// TEMPLATE: BETA10 0x1014c9f0
// MxListCursor<MxRegionLeftRight *>::Current

// TEMPLATE: BETA10 0x1014ca40
// MxListCursor<MxRegionLeftRight *>::Prepend

// TEMPLATE: BETA10 0x1014ca90
// MxListCursor<MxRegionLeftRight *>::Destroy

// TEMPLATE: BETA10 0x1014caf0
// MxListCursor<MxRegionLeftRight *>::HasMatch

// TEMPLATE: BETA10 0x1014cc10
// MxList<MxRegionTopBottom *>::DeleteAll

// TEMPLATE: BETA10 0x1014cd20
// MxListCursor<MxRegionTopBottom *>::Next

// TEMPLATE: BETA10 0x1014cda0
// MxListCursor<MxRegionTopBottom *>::Prev

// TEMPLATE: BETA10 0x1014ce70
// MxListCursor<MxRegionTopBottom *>::Prepend

// TEMPLATE: BETA10 0x1014cec0
// MxListCursor<MxRegionTopBottom *>::Destroy

// TEMPLATE: BETA10 0x1014cf50
// MxListEntry<MxRegionLeftRight *>::MxListEntry<MxRegionLeftRight *>

// TEMPLATE: BETA10 0x1014cf90
// MxListEntry<MxRegionLeftRight *>::GetPrev

// TEMPLATE: BETA10 0x1014cfb0
// MxListEntry<MxRegionLeftRight *>::SetPrev

// TEMPLATE: BETA10 0x1014cfe0
// MxListEntry<MxRegionLeftRight *>::GetNext

// TEMPLATE: BETA10 0x1014d000
// MxListEntry<MxRegionLeftRight *>::SetNext

// TEMPLATE: BETA10 0x1014d030
// MxListEntry<MxRegionLeftRight *>::GetValue

// TEMPLATE: BETA10 0x1014d090
// MxListEntry<MxRegionTopBottom *>::GetPrev

// TEMPLATE: BETA10 0x1014d0b0
// MxListEntry<MxRegionTopBottom *>::SetPrev

// TEMPLATE: BETA10 0x1014d0e0
// MxListEntry<MxRegionTopBottom *>::GetNext

// TEMPLATE: BETA10 0x1014d100
// MxListEntry<MxRegionTopBottom *>::SetNext

// TEMPLATE: BETA10 0x1014d130
// MxListEntry<MxRegionTopBottom *>::GetValue

// TEMPLATE: BETA10 0x1014d200
// MxList<MxRegionTopBottom *>::DeleteEntry

#endif // MXREGIONLIST_H
