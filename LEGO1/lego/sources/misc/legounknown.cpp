#include "legounknown.h"

#include "mxgeometry/mxmatrix.h"

DECOMP_SIZE_ASSERT(LegoUnknown, 0x50)

// FUNCTION: LEGO1 0x1009a0f0
LegoUnknown::LegoUnknown()
{
	for (LegoS32 i = 0; i < sizeOfArray(m_unk0x00); i++) {
		m_unk0x00[i].Clear();
	}
}

// FUNCTION: LEGO1 0x1009a130
LegoUnknown::~LegoUnknown()
{
}

// FUNCTION: LEGO1 0x1009a140
// FUNCTION: BETA10 0x10182c2f
void LegoUnknown::FUN_1009a140(
	const Vector3& p_point1,
	const Vector3& p_point2,
	const Vector3& p_point3,
	const Vector3& p_point4
)
{
	m_unk0x00[0] = p_point1;
	m_unk0x00[1] = p_point2;

	for (LegoS32 i = 0; i < 3; i++) {
		m_unk0x00[2][i] = (p_point3[i] - p_point1[i]) * 3.0f - p_point2[i] * 2.0f - p_point4[i];
		m_unk0x00[3][i] = (p_point1[i] - p_point3[i]) * 2.0f + p_point4[i] + p_point2[i];
	}
}

// FUNCTION: LEGO1 0x1009a1e0
// FUNCTION: BETA10 0x10182d61
LegoResult LegoUnknown::FUN_1009a1e0(float p_f1, Matrix4& p_mat, Vector3& p_v, LegoU32 p_und)
{
	Vector3 v1(p_mat[3]);
	Vector3 v2(p_mat[0]);
	Vector3 v3(p_mat[1]);
	Vector3 v4(p_mat[2]);

	if (p_f1 <= 0.001) {
		v1 = m_unk0x00[0];
		v4 = m_unk0x00[1];
	}
	else if (p_f1 >= 0.999) {
		v1 = m_unk0x00[0];
		v1 += m_unk0x00[1];
		v1 += m_unk0x00[2];
		v1 += m_unk0x00[3];

		for (LegoS32 i = 0; i < 3; i++) {
			v4[i] = m_unk0x00[1][i] + m_unk0x00[2][i] * 2.0f + m_unk0x00[3][i] * 3.0f;
		}
	}
	else {
		float local30 = p_f1 * p_f1;
		float local34 = local30 * p_f1;

		for (LegoS32 i = 0; i < 3; i++) {
			v1[i] = m_unk0x00[0][i] + m_unk0x00[1][i] * p_f1 + m_unk0x00[2][i] * local30 + m_unk0x00[3][i] * local34;
			v4[i] = m_unk0x00[1][i] + m_unk0x00[2][i] * p_f1 * 2.0f + m_unk0x00[3][i] * local30 * 3.0f;
		}
	}

	if (p_und) {
		v4 *= -1.0f;
	}

	if (v4.Unitize() != 0) {
		return FAILURE;
	}

	v2.EqualsCross(p_v, v4);
	if (v2.Unitize() != 0) {
		return FAILURE;
	}

	v3.EqualsCross(v4, v2);
	return SUCCESS;
}
