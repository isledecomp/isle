#ifndef __LEGOEDGE_H
#define __LEGOEDGE_H

#include "misc/legotypes.h"

class LegoWEEdge;
class Vector3;

// VTABLE: LEGO1 0x100db7b8
// SIZE 0x24
struct LegoEdge {
	LegoEdge();
	virtual ~LegoEdge(); // vtable+0x00

	LegoEdge* GetClockwiseEdge(LegoWEEdge& p_face);
	LegoEdge* GetCounterclockwiseEdge(LegoWEEdge& p_face);
	Vector3* CWVertex(LegoWEEdge& p_face);
	Vector3* CCWVertex(LegoWEEdge& p_face);

	LegoResult FUN_1002ddc0(LegoWEEdge& p_face, Vector3& p_point);

	// FUNCTION: BETA10 0x10184170
	LegoWEEdge* GetFaceA() { return m_faceA; }

	// FUNCTION: BETA10 0x10184190
	LegoWEEdge* GetFaceB() { return m_faceB; }

	// FUNCTION: BETA10 0x1001cb80
	Vector3* GetPointA() { return m_pointA; }

	// FUNCTION: BETA10 0x1001cbb0
	Vector3* GetPointB() { return m_pointB; }

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
