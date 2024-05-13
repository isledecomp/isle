#ifndef __LEGOUNKNOWN100DB7F4_H
#define __LEGOUNKNOWN100DB7F4_H

#include "legoedge.h"
#include "legoweedge.h"
#include "mxgeometry/mxgeometry3d.h"

// VTABLE: LEGO1 0x100db7f4
// SIZE 0x40
struct LegoUnknown100db7f4 : public LegoEdge {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04,
		c_bit4 = 0x08
	};

	LegoUnknown100db7f4();

	// FUNCTION: LEGO1 0x1002ddc0
	// FUNCTION: BETA10 0x100372a0
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

	LegoU32 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// SYNTHETIC: LEGO1 0x1009a6c0
	// LegoUnknown100db7f4::`scalar deleting destructor'

	LegoU16 m_flags;          // 0x24
	Mx3DPointFloat m_unk0x28; // 0x28
	LegoU32 m_unk0x3c;        // 0x3c
};

#endif // __LEGOUNKNOWN100DB7F4_H
