enum LegoEdgeFlag0 {
	c_edgeFlag0 = 1 << 0
};
enum LegoEdgeFlag1 {
	c_edgeFlag1 = 1 << 1
};
enum LegoEdgeFlag2 {
	c_edgeFlag2 = 1 << 2
};

#include "legopathedgecontainer.h"

// This translation unit exists to supply ONE out-of-line member of the
// LegoPathEdgeContainer red-black tree. Retail emits that member from a
// separate object, and it only reproduces byte-exactly when it is compiled in
// its own translation unit -- two of these members in one unit are never
// simultaneously exact. The declarations above the include are a stand-in for
// the 1997 source text that occupied this file; replace them if it is ever
// recovered.

// clang-format off
// MSVC 4.20 parses `>>` as a shift, so the closing angle brackets must stay split.
typedef list<LegoBoundaryEdge> BoundaryEdgeList;
// clang-format on

struct BoundaryEdgeInsertProbe : public BoundaryEdgeList {
	typedef iterator (BoundaryEdgeInsertProbe::*Fn)(iterator, const LegoBoundaryEdge&);
	static Fn Get();
};

BoundaryEdgeInsertProbe::Fn BoundaryEdgeInsertProbe::Get()
{
	return &BoundaryEdgeInsertProbe::insert;
}
