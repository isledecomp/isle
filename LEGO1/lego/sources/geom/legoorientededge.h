#ifndef __LEGOORIENTEDEDGE_H
#define __LEGOORIENTEDEDGE_H

#include "legoedge.h"
#include "legowegedge.h"
#include "mxgeometry/mxgeometry3d.h"

#include <assert.h>

// VTABLE: LEGO1 0x100db7f4
// VTABLE: BETA10 0x101c3794
// SIZE 0x40
struct LegoOrientedEdge : public LegoEdge {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_hasFaceA = 0x04,
		c_hasFaceB = 0x08
	};

	LegoOrientedEdge();

	// FUNCTION: LEGO1 0x1002ddc0
	// FUNCTION: BETA10 0x100372a0
	LegoResult GetFaceNormal(LegoWEEdge& p_face, Vector3& p_point) const
	{
		if (p_face.IsEqual(m_faceA)) {
			p_point[0] = -m_dir[0];
			p_point[1] = -m_dir[1];
			p_point[2] = -m_dir[2];
		}
		else {
			// clang-format off
			assert(p_face.IsEqual( m_faceB ));
			// clang-format on
			p_point = m_dir;
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
	LegoFloat DistanceBetweenMidpoints(const LegoOrientedEdge& p_other)
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
	// SYNTHETIC: BETA10 0x101840f0
	// LegoOrientedEdge::`scalar deleting destructor'

	// SYNTHETIC: BETA10 0x100bd390
	// LegoOrientedEdge::~LegoOrientedEdge

	LegoU16 m_flags;      // 0x24
	Mx3DPointFloat m_dir; // 0x28
	float m_length;       // 0x3c
};

// FUNCTION: LEGO1 0x10048c40
// FUNCTION: BETA10 0x1001cc90
inline LegoU32 LegoOrientedEdge::FUN_10048c40(const Vector3& p_position)
{
	LegoFloat localc, local10;
	LegoU32 result = FALSE;

	if (m_dir[0] > 0.001 || m_dir[0] < -0.001) {
		localc = (p_position[0] - (*m_pointA)[0]) / m_dir[0];

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

	if (m_dir[1] > 0.001 || m_dir[1] < -0.001) {
		local10 = (p_position[1] - (*m_pointA)[1]) / m_dir[1];

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

	if (m_dir[2] > 0.001 || m_dir[2] < -0.001) {
		local10 = (p_position[2] - (*m_pointA)[2]) / m_dir[2];

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

#endif // __LEGOORIENTEDEDGE_H
