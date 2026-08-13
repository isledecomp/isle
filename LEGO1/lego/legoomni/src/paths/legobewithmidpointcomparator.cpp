class LegoPathCounter0 {
public:
	int GetValue() { return m_value; }

private:
	int m_value;
};

#include "legopathedgecontainer.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoBEWithMidpointSet red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact. The declarations above the include are a stand-in for
// the 1997 source text that occupied this file; replace them if it is ever
// recovered.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef _Tree<
	LegoBEWithMidpoint*,
	LegoBEWithMidpoint*,
	LegoBEWithMidpointSet::_Kfn,
	LegoBEWithMidpointComparator,
	allocator<LegoBEWithMidpoint*>
> BEWithMidpointTree;
// clang-format on

struct BEWithMidpointLrotateProbe : public BEWithMidpointTree {
	typedef void (BEWithMidpointTree::*Fn)(_Nodeptr);
	static Fn Get();
};

BEWithMidpointLrotateProbe::Fn BEWithMidpointLrotateProbe::Get()
{
	return &BEWithMidpointTree::_Lrotate;
}
