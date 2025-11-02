#ifndef LEGOPATHEDGECONTAINER_H
#define LEGOPATHEDGECONTAINER_H

#include "mxgeometry/mxgeometry3d.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

class LegoPathBoundary;
struct LegoPathCtrlEdge;

// SIZE 0x08
struct LegoBoundaryEdge {
	LegoBoundaryEdge() {}

	// FUNCTION: BETA10 0x100bd620
	LegoBoundaryEdge(LegoPathCtrlEdge* p_edge, LegoPathBoundary* p_boundary)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
	}

	LegoPathCtrlEdge* m_edge;     // 0x00
	LegoPathBoundary* m_boundary; // 0x04

	int operator==(LegoBoundaryEdge) const { return 0; }
	int operator<(LegoBoundaryEdge) const { return 0; }
};

// SIZE 0x10
struct LegoBEWithFloat {
	LegoBEWithFloat()
	{
		m_edge = NULL;
		m_boundary = NULL;
		m_next = NULL;
		m_unk0x0c = 0.0f;
	}

	// FUNCTION: BETA10 0x100bd9a0
	LegoBEWithFloat(LegoPathCtrlEdge* p_edge, LegoPathBoundary* p_boundary, MxFloat p_unk0x0c)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
		m_next = NULL;
		m_unk0x0c = p_unk0x0c;
	}

	// FUNCTION: BETA10 0x100bd9f0
	LegoBEWithFloat(LegoPathCtrlEdge* p_edge, LegoPathBoundary* p_boundary, LegoBEWithFloat* p_next, MxFloat p_unk0x0c)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
		m_next = p_next;
		m_unk0x0c = p_unk0x0c;
	}

	LegoPathCtrlEdge* m_edge;     // 0x00
	LegoPathBoundary* m_boundary; // 0x04
	LegoBEWithFloat* m_next;      // 0x08
	MxFloat m_unk0x0c;            // 0x0c

	int operator==(LegoBEWithFloat) const { return 0; }
	int operator<(LegoBEWithFloat) const { return 0; }
};

struct LegoBEWithFloatComparator {
	// FUNCTION: BETA10 0x100bef80
	bool operator()(LegoBEWithFloat* const& p_a, LegoBEWithFloat* const& p_b) const
	{
		return p_a->m_unk0x0c < p_b->m_unk0x0c;
	}
};

typedef multiset<LegoBEWithFloat*, LegoBEWithFloatComparator> LegoBEWithFloatSet;

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

// SYNTHETIC: BETA10 0x10012080
// LegoPathEdgeContainer::`scalar deleting destructor'

// SYNTHETIC: BETA10 0x100120d0
// LegoPathEdgeContainer::~LegoPathEdgeContainer

#endif // LEGOPATHEDGECONTAINER_H
