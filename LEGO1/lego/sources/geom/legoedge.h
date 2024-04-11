#ifndef __LEGOEDGE_H
#define __LEGOEDGE_H

#include "misc/legotypes.h"
#include "realtime/vector.h"

class LegoWEEdge;

// VTABLE: LEGO1 0x100db7b8
// SIZE 0x24
struct LegoEdge {
	LegoEdge();
	virtual ~LegoEdge(); // vtable+0x00

	LegoEdge* GetClockwiseEdge(LegoWEEdge* face);
	LegoEdge* GetCounterclockwiseEdge(LegoWEEdge* face);
	Vector3* GetOpposingPoint(LegoWEEdge* face);
	Vector3* GetPoint(LegoWEEdge* face);

	LegoResult FUN_1002ddc0(LegoWEEdge* p_face, Vector3& p_point);

	// SYNTHETIC: LEGO1 0x1009a4a0
	// LegoEdge::`scalar deleting destructor'

	LegoWEEdge* m_faceA; // 0x04
	LegoWEEdge* m_faceB; // 0x08
	LegoEdge* m_ccwA;    // 0x0c
	LegoEdge* m_cwA;     // 0x10
	LegoEdge* m_ccwB;    // 0x14
	LegoEdge* m_cwB;     // 0x18
	Vector3* m_pointA;   // 0x1c
	Vector3* m_pointB;   // 0x20
};

#endif // __LEGOEDGE_H
