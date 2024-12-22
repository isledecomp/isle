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
		if (p_f.IsEqual(m_faceA)) {
			p_point[0] = -m_unk0x28.index_operator(0);
			p_point[1] = -m_unk0x28.index_operator(1);
			p_point[2] = -m_unk0x28.index_operator(2);
		}
		else {
			// clang-format off
			assert(p_f.IsEqual( m_faceB ));
			// clang-format on
			p_point = m_unk0x28;
		}

		return SUCCESS;
	}

	// FUNCTION: BETA10 0x1004a830
	LegoU32 BETA_1004a830(LegoWEGEdge& p_face, LegoU8 p_mask)
	{
		assert(p_face.IsEqual(m_faceA) || p_face.IsEqual(m_faceB));
		return (p_face.IsEqual(m_faceB) && (m_flags & c_bit1) && (p_face.GetMask0x03() & p_mask) == p_mask) ||
			   (p_face.IsEqual(m_faceA) && (m_flags & c_bit2) && (p_face.GetMask0x03() & p_mask) == p_mask);
	}

	// FUNCTION: BETA10 0x100b53b0
	LegoU32 BETA_100b53b0(LegoWEGEdge& p_face)
	{
		// clang-format off
		assert(p_face.IsEqual( m_faceA ) || p_face.IsEqual( m_faceB ));
		// clang-format on
		return (p_face.IsEqual(m_faceA) && (m_flags & c_bit1)) || (p_face.IsEqual(m_faceB) && (m_flags & c_bit2));
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

	// FUNCTION: BETA10 0x100bd4a0
	LegoFloat DistanceToMidpoint(const Vector3& p_vec)
	{
		Mx3DPointFloat point(*m_pointA);
		point += *m_pointB;
		point *= 0.5f;
		point -= p_vec;
		return sqrt((double) point.LenSquared());
	}

	// FUNCTION: BETA10 0x100bd540
	LegoFloat DistanceBetweenMidpoints(const LegoUnknown100db7f4& p_other)
	{
		Mx3DPointFloat point1(*m_pointA);
		Mx3DPointFloat point2(*p_other.m_pointA);
		point1 += *m_pointB;
		point1 *= 0.5f;
		point2 += *p_other.m_pointB;
		point2 *= 0.5f;
		point1 -= point2;
		return sqrt((double) point1.LenSquared());
	}

	// FUNCTION: BETA10 0x1001cc60
	LegoU32 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// FUNCTION: BETA10 0x101841b0
	void SetFlags(LegoU16 p_flags) { m_flags = p_flags; }

	inline LegoU32 FUN_10048c40(const Vector3& p_position);

	// SYNTHETIC: LEGO1 0x1009a6c0
	// LegoUnknown100db7f4::`scalar deleting destructor'

	LegoU16 m_flags;          // 0x24
	Mx3DPointFloat m_unk0x28; // 0x28
	float m_unk0x3c;          // 0x3c
};

// FUNCTION: LEGO1 0x10048c40
// FUNCTION: BETA10 0x1001cc90
inline LegoU32 LegoUnknown100db7f4::FUN_10048c40(const Vector3& p_position)
{
	LegoFloat localc, local10;
	LegoU32 result = FALSE;

	if (m_unk0x28[0] > 0.001 || m_unk0x28[0] < -0.001) {
		localc = (p_position[0] - (*m_pointA)[0]) / m_unk0x28[0];

		if (localc < 0 || localc > 1) {
			return FALSE;
		}

		result = TRUE;
	}
	else {
		if (p_position[0] > (*m_pointA)[0] + 0.001 || p_position[0] < (*m_pointA)[0] - 0.001) {
			return FALSE;
		}
	}

	if (m_unk0x28[1] > 0.001 || m_unk0x28[1] < -0.001) {
		local10 = (p_position[1] - (*m_pointA)[1]) / m_unk0x28[1];

		if (result) {
			if (localc > local10 + 0.001 || localc < local10 - 0.001) {
				return FALSE;
			}
		}
		else {
			result = TRUE;
			localc = local10;
		}
	}
	else {
		if (p_position[1] > (*m_pointA)[1] + 0.001 || p_position[1] < (*m_pointA)[1] - 0.001) {
			return FALSE;
		}
	}

	if (m_unk0x28[2] > 0.001 || m_unk0x28[2] < -0.001) {
		local10 = (p_position[2] - (*m_pointA)[2]) / m_unk0x28[2];

		if (result) {
			if (localc > local10 + 0.001 || localc < local10 - 0.001) {
				return FALSE;
			}
		}
		else {
			return TRUE;
		}
	}
	else {
		if (p_position[2] > (*m_pointA)[2] + 0.001 || p_position[2] < (*m_pointA)[2] - 0.001) {
			return FALSE;
		}
	}

	return TRUE;
}

#endif // __LEGOUNKNOWN100DB7F4_H
