#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "geom/legowegedge.h"
#include "legoanimpresenter.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

struct LegoPathBoundaryComparator {
	MxBool operator()(const undefined*, const undefined*) const { return 0; }
};

struct LegoAnimPresenterSetCompare {
	MxBool operator()(const LegoAnimPresenter*, const LegoAnimPresenter*) const { return 0; }
};

typedef set<LegoAnimPresenter*, LegoAnimPresenterSetCompare> LegoAnimPresenterSet;

// VTABLE: LEGO1 0x100d8618
// SIZE 0x74
class LegoPathBoundary : public LegoWEGEdge {
public:
	LegoPathBoundary();

	// STUB: LEGO1 0x10047a80
	// LegoPathBoundary::`scalar deleting destructor'
	inline LegoAnimPresenterSet* GetUnknown0x64() { return &m_unk0x64; }

private:
	map<undefined*, undefined*, LegoPathBoundaryComparator> m_unk0x54; // 0x54
	LegoAnimPresenterSet m_unk0x64;                                    // 0x64
};

// clang-format off
// GLOBAL: LEGO1 0x100f3200
// _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresenter *,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Kfn,LegoAnimPresenterSetCompare,allocator<LegoAnimPresenter *> >::_Nil
// clang-format on

#endif // LEGOPATHBOUNDARY_H
