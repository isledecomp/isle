class LegoPathRange0 {
public:
	int GetFirst() { return m_first; }
	int GetLast() { return m_last; }

private:
	int m_first;
	int m_last;
};

#include "legopathcontroller.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoPathCtrlEdgeSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact. The declarations above the include are a stand-in for
// the 1997 source text that occupied this file; replace them if it is ever
// recovered.

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

struct CtrlEdgeUboundProbe : public CtrlEdgeTree {
	typedef _Nodeptr (CtrlEdgeTree::*Fn)(LegoPathCtrlEdge* const&) const;
	static Fn Get();
};

CtrlEdgeUboundProbe::Fn CtrlEdgeUboundProbe::Get()
{
	return &CtrlEdgeTree::_Ubound;
}
