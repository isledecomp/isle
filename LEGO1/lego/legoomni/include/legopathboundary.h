#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "geom/legowegedge.h"
#include "legoanimpresenter.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoPathActor;

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

	MxResult AddActor(LegoPathActor* p_actor);

	inline LegoAnimPresenterSet* GetUnknown0x64() { return &m_unk0x64; }

	// STUB: LEGO1 0x10047a80
	// LegoPathBoundary::`scalar deleting destructor'

private:
	LegoPathActorSet m_unk0x54;     // 0x54
	LegoAnimPresenterSet m_unk0x64; // 0x64
};

// clang-format off
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
