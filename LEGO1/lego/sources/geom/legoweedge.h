#ifndef __LEGOWEEDGE_H
#define __LEGOWEEDGE_H

#include "decomp.h"
#include "misc/legotypes.h"

class LegoWEEdge;

// SIZE 0x24
struct Edge {
public:
	undefined4 m_unk0x00; // 0x00
	LegoWEEdge* m_faceA;  // 0x04
	LegoWEEdge* m_faceB;  // 0x08
	Edge* m_ccwA;         // 0x0c
	Edge* m_cwA;          // 0x10
	Edge* m_ccwB;         // 0x14
	Edge* m_cwB;          // 0x18
	void* m_pointA;       // 0x1c
	void* m_pointB;       // 0x20
};

// VTABLE: LEGO1 0x100db7c0
// SIZE 0x0c
class LegoWEEdge {
public:
	LegoWEEdge();
	virtual ~LegoWEEdge();           // vtable+0x00
	virtual LegoResult VTable0x04(); // vtable+0x04

	// SYNTHETIC: LEGO1 0x1009a570
	// LegoWEEdge::`scalar deleting destructor'

protected:
	LegoU8 m_numEdges; // 0x04
	Edge** m_edges;    // 0x08
};

#endif // __LEGOWEEDGE_H
