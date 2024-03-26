#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "geom/legowegedge.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

struct LegoPathBoundaryComparator {
	MxBool operator()(const undefined*, const undefined*) const { return 0; }
};

// SIZE 0x74
class LegoPathBoundary : public LegoWEGEdge {
public:
	LegoPathBoundary();

private:
	map<undefined*, undefined*, LegoPathBoundaryComparator> m_unk0x54; // 0x54
	map<undefined*, undefined*, LegoPathBoundaryComparator> m_unk0x64; // 0x64
};

#endif // LEGOPATHBOUNDARY_H
