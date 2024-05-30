#ifndef LEGOPATHEDGECONTAINER_H
#define LEGOPATHEDGECONTAINER_H

#include "mxgeometry/mxgeometry3d.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoPathBoundary;
struct LegoUnknown100db7f4;

// SIZE 0x08
struct LegoBoundaryEdge {
	LegoUnknown100db7f4* m_edge;  // 0x00
	LegoPathBoundary* m_boundary; // 0x04

	int operator==(LegoBoundaryEdge) const { return 0; }
	int operator<(LegoBoundaryEdge) const { return 0; }
};

// SIZE 0x3c
struct LegoPathEdgeContainer : public list<LegoBoundaryEdge> {
	enum {
		c_bit1 = 0x01
	};

	// FUNCTION: BETA10 0x100118e0
	LegoPathEdgeContainer()
	{
		m_boundary = NULL;
		m_flags = 0;
	}

	void SetBit1(MxU32 p_flag)
	{
		if (p_flag) {
			m_flags |= c_bit1;
		}
		else {
			m_flags &= ~c_bit1;
		}
	}

	MxU32 GetBit1() { return m_flags & c_bit1; }

	Mx3DPointFloat m_unk0x0c;     // 0x0c
	Mx3DPointFloat m_unk0x20;     // 0x20
	LegoPathBoundary* m_boundary; // 0x34
	MxU8 m_flags;                 // 0x38
};

#endif // LEGOPATHEDGECONTAINER_H
