#ifndef LEGOPATHBOUNDARY_H
#define LEGOPATHBOUNDARY_H

#include "misc/legowegedge.h"
#include "mxstl/stlcompat.h"

struct LegoPathBoundaryComparator {
	MxBool operator()(const void*, const void*) const { return 0; }
};

// SIZE 0x74
class LegoPathBoundary : public LegoWEGEdge {
public:
	LegoPathBoundary();

private:
	map<void*, void*, LegoPathBoundaryComparator> m_unk0x54; // 0x54
	map<void*, void*, LegoPathBoundaryComparator> m_unk0x64; // 0x64
};

#endif // LEGOPATHBOUNDARY_H
