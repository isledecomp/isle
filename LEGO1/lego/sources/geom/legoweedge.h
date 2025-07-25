#ifndef __LEGOWEEDGE_H
#define __LEGOWEEDGE_H

#include "decomp.h"
#include "misc/legotypes.h"

struct LegoOrientedEdge;

// VTABLE: LEGO1 0x100db7c0
// VTABLE: BETA10 0x101c3730
// SIZE 0x0c
class LegoWEEdge {
public:
	LegoWEEdge();
	virtual ~LegoWEEdge(); // vtable+0x00

	virtual LegoS32 LinkEdgesAndFaces(); // vtable+0x04

	// FUNCTION: BETA10 0x1001c980
	LegoU8 GetNumEdges() { return m_numEdges; }

	// FUNCTION: BETA10 0x1001cc30
	LegoOrientedEdge** GetEdges() { return m_edges; }

	// FUNCTION: BETA10 0x100373f0
	LegoU32 IsEqual(LegoWEEdge* p_other) { return this == p_other; }

	// FUNCTION: BETA10 0x100bd410
	void SetEdges(LegoOrientedEdge** p_edges, LegoU8 p_numEdges)
	{
		m_edges = p_edges;
		m_numEdges = p_numEdges;
	}

	// SYNTHETIC: LEGO1 0x1009a570
	// SYNTHETIC: BETA10 0x10182b70
	// LegoWEEdge::`scalar deleting destructor'

protected:
	LegoU8 m_numEdges;          // 0x04
	LegoOrientedEdge** m_edges; // 0x08
};

#endif // __LEGOWEEDGE_H
