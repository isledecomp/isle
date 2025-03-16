#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "geom/legowegedge.h"
#include "legoanimpresenter.h"
#include "legopathactor.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

#if defined(_M_IX86) || defined(__i386__)
#define COMPARE_POINTER_TYPE MxS32
#else
#define COMPARE_POINTER_TYPE MxS32*
#endif

struct LegoPathActorSetCompare {
	MxU32 operator()(const LegoPathActor* p_lhs, const LegoPathActor* p_rhs) const
	{
		return (COMPARE_POINTER_TYPE) p_lhs < (COMPARE_POINTER_TYPE) p_rhs;
	}
};

struct LegoAnimPresenterSetCompare {
	MxU32 operator()(const LegoAnimPresenter* p_lhs, const LegoAnimPresenter* p_rhs) const
	{
		return (COMPARE_POINTER_TYPE) p_lhs < (COMPARE_POINTER_TYPE) p_rhs;
	}
};

typedef set<LegoPathActor*, LegoPathActorSetCompare> LegoPathActorSet;
typedef set<LegoAnimPresenter*, LegoAnimPresenterSetCompare> LegoAnimPresenterSet;

// VTABLE: LEGO1 0x100d8618
// SIZE 0x74
class LegoPathBoundary : public LegoWEGEdge {
public:
	LegoPathBoundary();
	~LegoPathBoundary() override;

	MxResult AddActor(LegoPathActor* p_actor);
	MxResult RemoveActor(LegoPathActor* p_actor);
	void FUN_100575b0(Vector3& p_point1, Vector3& p_point2, LegoPathActor* p_actor);
	void SwitchBoundary(
		LegoPathActor* p_actor,
		LegoPathBoundary*& p_boundary,
		LegoUnknown100db7f4*& p_edge,
		float& p_unk0xe4
	);
	MxU32 Intersect(
		float p_scale,
		Vector3& p_point1,
		Vector3& p_point2,
		Vector3& p_point3,
		LegoUnknown100db7f4*& p_edge
	);
	MxU32 FUN_10057fe0(LegoAnimPresenter* p_presenter);
	MxU32 FUN_100586e0(LegoAnimPresenter* p_presenter);

	// FUNCTION: BETA10 0x1001ffb0
	LegoPathActorSet& GetActors() { return m_actors; }

	// FUNCTION: BETA10 0x10082b10
	LegoAnimPresenterSet& GetPresenters() { return m_presenters; }

	// SYNTHETIC: LEGO1 0x10047a80
	// LegoPathBoundary::`vector deleting destructor'

private:
	LegoPathActorSet m_actors;         // 0x54
	LegoAnimPresenterSet m_presenters; // 0x64
};

// clang-format off
// TEMPLATE: LEGO1 0x1002bee0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::~_Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,a

// TEMPLATE: LEGO1 0x1002bfb0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x1002bff0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::erase

// TEMPLATE: LEGO1 0x1002c440
// TEMPLATE: BETA10 0x100b6480
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::find

// TEMPLATE: LEGO1 0x1002c4c0
// ?_Copy@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXABV1@@Z

// TEMPLATE: LEGO1 0x1002c5b0
// ?_Copy@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x1002c630
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Erase

// TEMPLATE: LEGO1 0x1002c670
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::~set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >

// TEMPLATE: LEGO1 0x1002c6c0
// TEMPLATE: BETA10 0x10020760
// Set<LegoPathActor *,LegoPathActorSetCompare>::~Set<LegoPathActor *,LegoPathActorSetCompare>

// TEMPLATE: LEGO1 0x1002eb10
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Init

// TEMPLATE: LEGO1 0x1002ebc0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Min

// TEMPLATE: LEGO1 0x100822a0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Min

// TEMPLATE: LEGO1 0x10045d80
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10045dd0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Insert

// TEMPLATE: LEGO1 0x10046310
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::insert

// TEMPLATE: LEGO1 0x10046580
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Lrotate

// TEMPLATE: LEGO1 0x100465e0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Rrotate

// TEMPLATE: LEGO1 0x1004a7a0
// ?_Construct@@YAXPAPAVLegoPathActor@@ABQAV1@@Z

// TEMPLATE: LEGO1 0x10056c20
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::~_Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoA

// TEMPLATE: LEGO1 0x10056cf0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10056d30
// ?erase@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10057180
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Erase

// TEMPLATE: LEGO1 0x100571c0
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::~set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >

// TEMPLATE: LEGO1 0x10057210
// Set<LegoAnimPresenter *,LegoAnimPresenterSetCompare>::~Set<LegoAnimPresenter *,LegoAnimPresenterSetCompare>

// TEMPLATE: BETA10 0x10082de0
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::begin

// TEMPLATE: LEGO1 0x100573e0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::begin

// TEMPLATE: LEGO1 0x100580c0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::insert

// TEMPLATE: LEGO1 0x10058330
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10058380
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Buynode

// TEMPLATE: LEGO1 0x100583a0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Insert

// TEMPLATE: LEGO1 0x10058620
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Lrotate

// TEMPLATE: LEGO1 0x10058680
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Rrotate

// TEMPLATE: LEGO1 0x10058820
// ?erase@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AViterator@1@V21@0@Z

// TEMPLATE: LEGO1 0x100588e0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::equal_range

// TEMPLATE: LEGO1 0x10058950
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Lbound

// TEMPLATE: LEGO1 0x10058980
// ?_Construct@@YAXPAPAVLegoAnimPresenter@@ABQAV1@@Z

// TEMPLATE: LEGO1 0x100589a0
// _Distance

// TEMPLATE: LEGO1 0x10081cd0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::lower_bound

// TEMPLATE: BETA10 0x10082b90
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::const_iterator::operator++

// TEMPLATE: BETA10 0x10082ee0
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::end

// TEMPLATE: BETA10 0x10082b40
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::const_iterator::operator*

// TEMPLATE: BETA10 0x10021dc0
// Set<LegoPathActor *,LegoPathActorSetCompare>::Set<LegoPathActor *,LegoPathActorSetCompare>

// TEMPLATE: BETA10 0x100202d0
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::begin

// TEMPLATE: BETA10 0x10020030
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::const_iterator::operator++

// TEMPLATE: BETA10 0x100203d0
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::end

// GLOBAL: LEGO1 0x100f11a4
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Nil

// GLOBAL: LEGO1 0x100f3200
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Nil
// clang-format on

#endif // LEGOPATHBOUNDARY_H
