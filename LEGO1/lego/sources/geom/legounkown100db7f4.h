#ifndef __LEGOUNKNOWN100DB7F4_H
#define __LEGOUNKNOWN100DB7F4_H

#include "legoedge.h"
#include "legowegedge.h"
#include "mxgeometry/mxgeometry3d.h"

#include <assert.h>

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
			// clang-format off
			// FIXME: There is no * dereference in the original assertion
			assert(p_f.IsEqual( *m_faceB ));
			// clang-format on
			p_point = m_unk0x28;
		}

		return SUCCESS;
	}

	// FUNCTION: BETA10 0x1004a830
	LegoU32 Unknown(LegoWEGEdge& p_face, LegoU8 p_mask)
	{
		return (p_face.IsEqual(*m_faceB) && (m_flags & c_bit1) && (p_face.GetMask0x03() & p_mask) == p_mask) ||
			   (p_face.IsEqual(*m_faceA) && (m_flags & c_bit2) && (p_face.GetMask0x03() & p_mask) == p_mask);
	}

	// FUNCTION: BETA10 0x100b53b0
	LegoU32 Unknown2(LegoWEGEdge& p_face)
	{
		return (p_face.IsEqual(*m_faceA) && (m_flags & c_bit1)) || (p_face.IsEqual(*m_faceB) && (m_flags & c_bit2));
	}

	// FUNCTION: BETA10 0x1001cbe0
	LegoWEEdge* OtherFace(LegoWEEdge* p_other)
	{
		if (m_faceA == p_other) {
			return m_faceB;
		}
		else {
			return m_faceA;
		}
	}

	LegoU32 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// SYNTHETIC: LEGO1 0x1009a6c0
	// LegoUnknown100db7f4::`scalar deleting destructor'

	LegoU16 m_flags;          // 0x24
	Mx3DPointFloat m_unk0x28; // 0x28
	float m_unk0x3c;          // 0x3c
};

#endif // __LEGOUNKNOWN100DB7F4_H
