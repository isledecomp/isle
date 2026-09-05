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
// VTABLE: BETA10 0x101bdd58
// SIZE 0x74
class LegoPathBoundary : public LegoWEGEdge {
public:
	LegoPathBoundary();
	~LegoPathBoundary() override;

	MxResult AddActor(LegoPathActor* p_actor);
	MxResult RemoveActor(LegoPathActor* p_actor);
	void CheckAndCallPathTriggers(Vector3& p_from, Vector3& p_to, LegoPathActor* p_actor);
	void SwitchBoundary(
		LegoPathActor* p_actor,
		LegoPathBoundary*& p_boundary,
		LegoOrientedEdge*& p_edge,
		float& p_scale
	);
	MxU32 Intersect(
		float p_scale,
		Vector3& p_oldPos,
		Vector3& p_newPos,
		Vector3& p_intersectionPoint,
		LegoOrientedEdge*& p_edge
	);
	MxU32 AddPresenterIfInRange(LegoAnimPresenter* p_presenter);
	MxU32 RemovePresenter(LegoAnimPresenter* p_presenter);
	MxU32 BETA_100b23bb(const Vector3& p_position, LegoOrientedEdge*& p_edge);

	// FUNCTION: BETA10 0x1001ffb0
	LegoPathActorSet& GetActors() { return m_actors; }

	// FUNCTION: BETA10 0x10082b10
	LegoAnimPresenterSet& GetPresenters() { return m_presenters; }

	// SYNTHETIC: LEGO1 0x10047a80
	// SYNTHETIC: BETA10 0x100bd300
	// LegoPathBoundary::`vector deleting destructor'

private:
	LegoPathActorSet m_actors;         // 0x54
	LegoAnimPresenterSet m_presenters; // 0x64
};

// clang-format off
// TEMPLATE: LEGO1 0x1002bee0 SYMBOL
// ??1?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1002bfb0 SYMBOL
// ?_Inc@iterator@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x1002bff0 SYMBOL
// ?erase@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x1002c440 SYMBOL
// TEMPLATE: BETA10 0x10020480 SYMBOL
// ?find@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QBE?AVconst_iterator@1@ABQAVLegoPathActor@@@Z

// TEMPLATE: LEGO1 0x1002c4c0
// ?_Copy@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXABV1@@Z

// TEMPLATE: LEGO1 0x1002c5b0
// ?_Copy@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x1002c630 SYMBOL
// ?_Erase@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1002c670 SYMBOL
// ??1?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1002c6c0
// TEMPLATE: BETA10 0x10020760
// Set<LegoPathActor *,LegoPathActorSetCompare>::~Set<LegoPathActor *,LegoPathActorSetCompare>

// TEMPLATE: LEGO1 0x1002eb10 SYMBOL
// ?_Init@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXXZ

// TEMPLATE: LEGO1 0x1002ebc0 SYMBOL
// ?_Min@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@KAPAU_Node@1@PAU21@@Z

// TEMPLATE: LEGO1 0x100822a0 SYMBOL
// ?_Min@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@KAPAU_Node@1@PAU21@@Z

// TEMPLATE: LEGO1 0x10045d80 SYMBOL
// ?_Dec@iterator@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10045dd0 SYMBOL
// ?_Insert@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAE?AViterator@1@PAU_Node@1@0ABQAVLegoPathActor@@@Z

// TEMPLATE: LEGO1 0x10046310 SYMBOL
// ?insert@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE?AU?$pair@Viterator@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$se

// TEMPLATE: LEGO1 0x10046580 SYMBOL
// ?_Lrotate@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x100465e0 SYMBOL
// ?_Rrotate@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1004a7a0
// ?_Construct@@YAXPAPAVLegoPathActor@@ABQAV1@@Z

// TEMPLATE: LEGO1 0x10056c20 SYMBOL
// ??1?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10056cf0 SYMBOL
// ?_Inc@iterator@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10056d30
// ?erase@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x10057180 SYMBOL
// ?_Erase@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x100571c0 SYMBOL
// ??1?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10057210
// Set<LegoAnimPresenter *,LegoAnimPresenterSetCompare>::~Set<LegoAnimPresenter *,LegoAnimPresenterSetCompare>

// TEMPLATE: BETA10 0x10082de0
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::begin

// TEMPLATE: LEGO1 0x100573e0 SYMBOL
// ?begin@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE?AViterator@1@XZ

// TEMPLATE: LEGO1 0x100580c0 SYMBOL
// ?insert@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AU?$pair@Viterator@?$_Tree@PAVLegoAn

// TEMPLATE: LEGO1 0x10058330 SYMBOL
// ?_Dec@iterator@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10058380 SYMBOL
// ?_Buynode@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IAEPAU_Node@1@PAU21@W4_Redbl@1@@Z

// TEMPLATE: LEGO1 0x100583a0 SYMBOL
// ?_Insert@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IAE?AViterator@1@PAU_Node@1@0ABQAVLegoA

// TEMPLATE: LEGO1 0x10058620 SYMBOL
// ?_Lrotate@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10058680 SYMBOL
// ?_Rrotate@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x10058820
// ?erase@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AViterator@1@V21@0@Z

// TEMPLATE: LEGO1 0x100588e0 SYMBOL
// ?equal_range@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AU?$pair@Viterator@?$_Tree@PAVL

// TEMPLATE: LEGO1 0x10058950 SYMBOL
// ?_Lbound@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@IBEPAU_Node@1@ABQAVLegoAnimPresenter@@@

// TEMPLATE: LEGO1 0x10058980
// ?_Construct@@YAXPAPAVLegoAnimPresenter@@ABQAV1@@Z

// TEMPLATE: LEGO1 0x100589a0
// _Distance

// TEMPLATE: LEGO1 0x10081cd0 SYMBOL
// ?lower_bound@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QBE?AVconst_iterator@1@ABQAVLegoPathActor@@@Z

// TEMPLATE: BETA10 0x10082b90
// ??Econst_iterator@?$_Tree@PAVLegoAnimPresenter@@PAV1@U_Kfn@?$set@PAVLegoAnimPresenter@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@ULegoAnimPresenterSetCompare@@V?$allocator@PAVLegoAnimPresenter@@@@@@QAE?AV01@H@Z

// TEMPLATE: BETA10 0x10082ee0
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::end

// TEMPLATE: BETA10 0x10082b40
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::const_iterator::operator*

// TEMPLATE: BETA10 0x100b6440
// set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::find

// TEMPLATE: BETA10 0x100b6480
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::find

// TEMPLATE: BETA10 0x10021dc0
// ??0?$Set@PAVLegoPathActor@@ULegoPathActorSetCompare@@@@QAE@ABV0@@Z

// TEMPLATE: BETA10 0x100202d0
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::begin

// TEMPLATE: BETA10 0x10020030
// ??Econst_iterator@?$_Tree@PAVLegoPathActor@@PAV1@U_Kfn@?$set@PAVLegoPathActor@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@ULegoPathActorSetCompare@@V?$allocator@PAVLegoPathActor@@@@@@QAE?AV01@H@Z

// TEMPLATE: BETA10 0x100203d0
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::end

// GLOBAL: LEGO1 0x100f11a4
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *>>::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *>>::_Nil

// GLOBAL: LEGO1 0x100f3200
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *>>::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *>>::_Nil
// clang-format on

#endif // LEGOPATHBOUNDARY_H
