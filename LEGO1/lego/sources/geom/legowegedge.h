#ifndef __LEGOWEGEDGE_H
#define __LEGOWEGEDGE_H

class LegoPathStruct;

#include "decomp.h"
#include "legoedge.h"
#include "legoweedge.h"

// This struct might have been defined elsewhere (legopathstruct.h?).
// Must be defined before the inclusion of Mx4DPointFloat for correct order
// SIZE 0x0c
struct PathWithTrigger {
	// FUNCTION: LEGO1 0x10048280
	// FUNCTION: BETA10 0x100bd450
	PathWithTrigger()
	{
		m_pathStruct = NULL;
		m_data = 0;
		m_triggerLength = 0.0f;
	}

	LegoPathStruct* m_pathStruct; // 0x00
	unsigned int m_data;          // 0x04
	float m_triggerLength;        // 0x08
};

#include "realtime/vector3d.inl.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxgeometry/mxgeometry4d.h"

#include <assert.h>

// might be a struct with public members
// VTABLE: LEGO1 0x100db7f8
// VTABLE: BETA10 0x101c3798
// SIZE 0x54
class LegoWEGEdge : public LegoWEEdge {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02,
		c_bit3 = 0x04,
		c_visible = 0x10
	};

	LegoWEGEdge();
	~LegoWEGEdge() override;

	LegoS32 LinkEdgesAndFaces() override; // vtable+0x04

	// FUNCTION: BETA10 0x100270c0
	LegoU32 GetVisibility()
	{
		if (m_flags & c_visible) {
			return FALSE;
		}
		else {
			return TRUE;
		}
	}

	// TODO: Other BETA10 reference at 0x1001c9e0, not sure what is going on
	// FUNCTION: BETA10 0x1001ff80
	Mx4DPointFloat* GetUp() { return &m_up; }

	// FUNCTION: BETA10 0x1001ca10
	Mx4DPointFloat* GetEdgeNormal(int index) { return &m_edgeNormals[index]; }

	// FUNCTION: BETA10 0x1001c9b0
	const LegoChar* GetName() { return m_name; }

	// FUNCTION: BETA10 0x1005d5f0
	void SetVisibility(LegoU32 p_disable)
	{
		if (p_disable) {
			m_flags &= ~c_visible;
		}
		else {
			m_flags |= c_visible;
		}
	}

	// FUNCTION: BETA10 0x1004a980
	LegoU8 GetMask0x03() { return m_flags & (c_bit1 | c_bit2); }

	// SYNTHETIC: LEGO1 0x1009a7e0
	// SYNTHETIC: BETA10 0x10184130
	// LegoWEGEdge::`scalar deleting destructor'

	friend class LegoPathController;

protected:
	LegoS32 ValidateFacePlanarity();

	LegoU8 m_flags;                 // 0x0c
	LegoU8 m_unk0x0d;               // 0x0d
	LegoChar* m_name;               // 0x10
	Mx4DPointFloat m_up;            // 0x14
	Mx4DPointFloat* m_edgeNormals;  // 0x2c
	Mx3DPointFloat m_centerPoint;   // 0x30
	float m_boundingRadius;         // 0x44
	LegoU8 m_numTriggers;           // 0x48
	PathWithTrigger* m_pathTrigger; // 0x4c
	Mx3DPointFloat* m_direction;    // 0x50
};

// In 1997 the LegoOrientedEdge class and its inlines lived in this header
// (BETA10 places their assert sites at legowegedge.h lines 179-253);
// legoorientededge.h was a decompilation-era split, now re-merged.
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

	// FUNCTION: BETA10 0x100b53b0
	LegoU32 BETA_100b53b0(LegoWEGEdge& p_face)
	{
		// clang-format off
		assert(p_face.IsEqual( m_faceA ) || p_face.IsEqual( m_faceB ));
		// clang-format on
		return (p_face.IsEqual(m_faceA) && (m_flags & c_bit1)) || (p_face.IsEqual(m_faceB) && (m_flags & c_bit2));
	}

	// FUNCTION: BETA10 0x1004a830
	LegoU32 BETA_1004a830(LegoWEGEdge& p_face, LegoU8 p_mask)
	{
		assert(p_face.IsEqual(m_faceA) || p_face.IsEqual(m_faceB));
		return (p_face.IsEqual(m_faceB) && (m_flags & c_bit1) && (p_face.GetMask0x03() & p_mask) == p_mask) ||
			   (p_face.IsEqual(m_faceA) && (m_flags & c_bit2) && (p_face.GetMask0x03() & p_mask) == p_mask);
	}

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

#endif // __LEGOWEGEDGE_H
