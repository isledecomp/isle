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
struct LegoBEWithMidpoint {
	LegoBEWithMidpoint()
	{
		m_edge = NULL;
		m_boundary = NULL;
		m_next = NULL;
		m_distanceToMidpoint = 0.0f;
	}

	// FUNCTION: BETA10 0x100bd9a0
	LegoBEWithMidpoint(LegoPathCtrlEdge* p_edge, LegoPathBoundary* p_boundary, MxFloat p_distanceToMidpoint)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
		m_next = NULL;
		m_distanceToMidpoint = p_distanceToMidpoint;
	}

	// FUNCTION: BETA10 0x100bd9f0
	LegoBEWithMidpoint(
		LegoPathCtrlEdge* p_edge,
		LegoPathBoundary* p_boundary,
		LegoBEWithMidpoint* p_next,
		MxFloat p_distanceToMidpoint
	)
	{
		m_edge = p_edge;
		m_boundary = p_boundary;
		m_next = p_next;
		m_distanceToMidpoint = p_distanceToMidpoint;
	}

	LegoPathCtrlEdge* m_edge;     // 0x00
	LegoPathBoundary* m_boundary; // 0x04
	LegoBEWithMidpoint* m_next;   // 0x08
	MxFloat m_distanceToMidpoint; // 0x0c

	int operator==(LegoBEWithMidpoint) const { return 0; }
	int operator<(LegoBEWithMidpoint) const { return 0; }
};

struct LegoBEWithMidpointComparator {
	// FUNCTION: BETA10 0x100bef80
	bool operator()(LegoBEWithMidpoint* const& p_a, LegoBEWithMidpoint* const& p_b) const
	{
		return p_a->m_distanceToMidpoint < p_b->m_distanceToMidpoint;
	}
};

typedef multiset<LegoBEWithMidpoint*, LegoBEWithMidpointComparator> LegoBEWithMidpointSet;

// SIZE 0x3c
struct LegoPathEdgeContainer : public list<LegoBoundaryEdge> {
	enum {
		c_hasPath = 0x01
	};

	// FUNCTION: BETA10 0x100118e0
	LegoPathEdgeContainer()
	{
		m_boundary = NULL;
		m_flags = 0;
	}

	// FUNCTION: BETA10 0x100bd660
	void SetPath(MxU32 p_set)
	{
		if (p_set) {
			m_flags |= c_hasPath;
		}
		else {
			m_flags &= ~c_hasPath;
		}
	}

	// FUNCTION: BETA10 0x1001cb50
	MxU32 HasPath() { return m_flags & c_hasPath; }

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
