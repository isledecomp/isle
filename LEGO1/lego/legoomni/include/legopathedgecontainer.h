#ifndef LEGOPATHEDGECONTAINER_H
#define LEGOPATHEDGECONTAINER_H

#include "mxgeometry/mxgeometry3d.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoPathBoundary;
struct LegoPathCtrlEdge;
struct LegoUnknown100db7f4;

// SIZE 0x08
struct LegoBoundaryEdge {
	LegoBoundaryEdge() {}

	// FUNCTION: BETA10 0x100bd620
	LegoBoundaryEdge(LegoUnknown100db7f4* p_edge, LegoPathBoundary* p_boundary)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
	}

	LegoUnknown100db7f4* m_edge;  // 0x00
	LegoPathBoundary* m_boundary; // 0x04

	int operator==(LegoBoundaryEdge) const { return 0; }
	int operator<(LegoBoundaryEdge) const { return 0; }
};

// SIZE 0x10
struct LegoBoundaryEdgeWithFloat {
	LegoBoundaryEdgeWithFloat()
	{
		m_edge = NULL;
		m_boundary = NULL;
		m_unk0x08 = 0;
		m_unk0x0c = 0.0f;
	}

	// FUNCTION: BETA10 0x100bd9a0
	LegoBoundaryEdgeWithFloat(LegoPathCtrlEdge* p_edge, LegoPathBoundary* p_boundary, MxFloat p_unk0x0c)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
		m_unk0x08 = 0;
		m_unk0x0c = p_unk0x0c;
	}

	LegoPathCtrlEdge* m_edge;     // 0x00
	LegoPathBoundary* m_boundary; // 0x04
	undefined4 m_unk0x08;         // 0x08
	MxFloat m_unk0x0c;            // 0x0c

	int operator==(LegoBoundaryEdgeWithFloat) const { return 0; }
	int operator<(LegoBoundaryEdgeWithFloat) const { return 0; }
};

struct LegoBoundaryEdgeWithFloatComparator {
	// FUNCTION: BETA10 0x100bef80
	bool operator()(LegoBoundaryEdgeWithFloat* const& p_a, LegoBoundaryEdgeWithFloat* const& p_b) const
	{
		return p_a->m_unk0x0c < p_b->m_unk0x0c;
	}
};

typedef multiset<LegoBoundaryEdgeWithFloat*, LegoBoundaryEdgeWithFloatComparator> LegoBoundaryEdgeWithFloatSet;

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

	// FUNCTION: BETA10 0x100bd660
	void SetBit1(MxU32 p_set)
	{
		if (p_set) {
			m_flags |= c_bit1;
		}
		else {
			m_flags &= ~c_bit1;
		}
	}

	// FUNCTION: BETA10 0x1001cb50
	MxU32 GetBit1() { return m_flags & c_bit1; }

	Mx3DPointFloat m_position;    // 0x0c
	Mx3DPointFloat m_direction;   // 0x20
	LegoPathBoundary* m_boundary; // 0x34
	MxU8 m_flags;                 // 0x38
};

#endif // LEGOPATHEDGECONTAINER_H
