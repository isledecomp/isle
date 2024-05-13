#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "geom/legowegedge.h"
#include "legoanimpresenter.h"
#include "legopathactor.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

struct LegoPathActorSetCompare {
	MxU32 operator()(const LegoPathActor* p_lhs, const LegoPathActor* p_rhs) const
	{
		return (MxS32) p_lhs < (MxS32) p_rhs;
	}
};

struct LegoAnimPresenterSetCompare {
	MxBool operator()(const LegoAnimPresenter* p_lhs, const LegoAnimPresenter* p_rhs) const { return 0; }
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
	MxU32 Intersect(float p_scale, Vector3& p_point1, Vector3& p_point2, Vector3& p_point3, LegoEdge*& p_edge);
	MxU32 FUN_10057fe0(LegoAnimPresenter* p_presenter);
	MxU32 FUN_100586e0(LegoAnimPresenter* p_presenter);

	inline LegoPathActorSet& GetActors() { return m_actors; }
	inline LegoAnimPresenterSet& GetPresenters() { return m_presenters; }

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
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::find

// TEMPLATE: LEGO1 0x1002c4c0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Copy

// TEMPLATE: LEGO1 0x1002c630
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Erase

// TEMPLATE: LEGO1 0x1002c670
// set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::~set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >

// TEMPLATE: LEGO1 0x1002c6c0
// Set<LegoPathActor *,LegoPathActorSetCompare>::~Set<LegoPathActor *,LegoPathActorSetCompare>

// TEMPLATE: LEGO1 0x1002eb10
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Init

// TEMPLATE: LEGO1 0x1002ebc0
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Min

// TEMPLATE: LEGO1 0x10045d80
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::iterator::_Dec

// TEMPLATE: LEGO1 0x10045dd0
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Insert

// GLOBAL: LEGO1 0x100f11a4
// _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Kfn,LegoPathActorSetCompare,allocator<LegoPathActor *> >::_Nil

// GLOBAL: LEGO1 0x100f3200
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Nil
// clang-format on

#endif // LEGOPATHBOUNDARY_H
