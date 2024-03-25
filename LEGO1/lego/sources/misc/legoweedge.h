#ifndef __LEGOWEEDGE_H
#define __LEGOWEEDGE_H

#include "decomp.h"
#include "legotypes.h"

class LegoWEEdge;

// SIZE 0x24
class Edge {
	virtual ~Edge()
	{
		// TODO
	}
	LegoWEEdge* m_faceA; // 0x04
	LegoWEEdge* m_faceB; // 0x08
	Edge* m_ccwA;        // 0x0c
	Edge* m_cwA;         // 0x10
	Edge* m_ccwB;        // 0x14
	Edge* m_cwB;         // 0x18
	void* m_pointA;      // 0x1c
	void* m_pointB;      // 0x20
};

// SIZE 0x08
struct EdgePair {
	Edge* m_e1; // 0x00
	Edge* m_e2; // 0x04
};

// SIZE 0x0c
class LegoWEEdge {
public:
	LegoWEEdge();
	virtual ~LegoWEEdge()
	{
		// TODO
	}

private:
	LegoU8 m_numEdges; // 0x04
	EdgePair* m_edges; // 0x08
};

#endif // __LEGOWEEDGE_H
