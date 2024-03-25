#ifndef __LEGOWEGEDGE_H
#define __LEGOWEGEDGE_H

#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxtypes.h"

// SIZE 0x54
class LegoWEGEdge : public LegoWEEdge {
public:
	LegoWEGEdge();

	inline MxBool GetFlag0x10() { return m_unk0x0c & 0x10 ? FALSE : TRUE; }

private:
	LegoU8 m_unk0x0c;              // 0x0c
	LegoU8 m_unk0x0d;              // 0x0d
	char* m_name;                  // 0x10
	Mx4DPointFloat m_unk0x14;      // 0x14
	Mx4DPointFloat* m_edgeNormals; // 0x2c
	Mx3DPointFloat m_unk0x30;      // 0x30
	LegoU32 m_unk0x44;             // 0x44
	LegoU8 m_unk0x48;              // 0x48
	LegoU32 m_unk0x4c;             // 0x4c
	LegoU32 m_unk0x50;             // 0x50
};

#endif // __LEGOWEGEDGE_H
