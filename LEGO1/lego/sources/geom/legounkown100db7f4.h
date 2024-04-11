#ifndef __LEGOUNKNOWN100DB7F4_H
#define __LEGOUNKNOWN100DB7F4_H

#include "legoedge.h"
#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"

// VTABLE: LEGO1 0x100db7f4
// SIZE 0x40
class LegoUnknown100db7f4 : public LegoEdge {
public:
	// FUNCTION: LEGO1 0x1002ddc0
	LegoResult FUN_1002ddc0(LegoWEEdge& p_f, Vector3& p_point)
	{
		if (p_f.IsEqual(*m_faceA)) {
			p_point[0] = -m_unk0x28[0];
			p_point[1] = -m_unk0x28[1];
			p_point[2] = -m_unk0x28[2];
		}
		else {
			p_point = m_unk0x28;
		}

		return SUCCESS;
	}

private:
	LegoU16 m_unk0x24;        // 0x24
	Mx3DPointFloat m_unk0x28; // 0x28
	LegoU32 m_unk0x3c;        // 0x3c
};

#endif // __LEGOUNKNOWN100DB7F4_H
