#include "legopathcontroller.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoPathCtrlEdgeSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoPathCtrlEdge*,
	LegoPathCtrlEdge*,
	LegoPathCtrlEdgeSet::_Kfn,
	LegoPathCtrlEdgeCompare,
	allocator<LegoPathCtrlEdge*>
> CtrlEdgeTree;
// clang-format on

struct CtrlEdgeFindProbe : public CtrlEdgeTree {
	typedef const_iterator (CtrlEdgeTree::*Fn)(const key_type&) const;
	static Fn Get();
};

CtrlEdgeFindProbe::Fn CtrlEdgeFindProbe::Get()
{
	return &CtrlEdgeTree::find;
}
