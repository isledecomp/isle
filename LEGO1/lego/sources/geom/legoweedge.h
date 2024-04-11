#ifndef __LEGOWEEDGE_H
#define __LEGOWEEDGE_H

#include "decomp.h"
#include "legoedge.h"
#include "misc/legotypes.h"

// VTABLE: LEGO1 0x100db7c0
// SIZE 0x0c
class LegoWEEdge {
public:
	LegoWEEdge();
	virtual ~LegoWEEdge(); // vtable+0x00

	virtual LegoResult VTable0x04(); // vtable+0x04

	inline LegoU8 GetNumEdges() { return m_numEdges; }
	inline LegoU32 IsEqual(LegoWEEdge& p_other) { return this == &p_other; }

	// SYNTHETIC: LEGO1 0x1009a570
	// LegoWEEdge::`scalar deleting destructor'

protected:
	LegoU8 m_numEdges;  // 0x04
	LegoEdge** m_edges; // 0x08
};

#endif // __LEGOWEEDGE_H
