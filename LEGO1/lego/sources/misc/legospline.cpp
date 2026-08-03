// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordYJ {};
class MxUnkRecordYK {};
class MxUnkRecordYL {};

#include "legospline.h"

#include "mxgeometry/mxmatrix.h"
// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.
class RkM0 {
public:
	void rkm0() {}
};
class RkM1 {
public:
	void rkm1() {}
};
class RkM2 {
public:
	void rkm2() {}
};
class RkM3 {
public:
	void rkm3() {}
};
class RkM4 {
public:
	void rkm4() {}
};
class RkM5 {
public:
	void rkm5() {}
};
class RkM6 {
public:
	void rkm6() {}
};
class RkM7 {
public:
	void rkm7() {}
};
class RkM8 {
public:
	void rkm8() {}
};
class RkM9 {
public:
	void rkm9() {}
};
class RkM10 {
public:
	void rkm10() {}
};
class RkM11 {
public:
	void rkm11() {}
};
class RkM12 {
public:
	void rkm12() {}
};
class RkM13 {
public:
	void rkm13() {}
};

DECOMP_SIZE_ASSERT(LegoSpline, 0x50)

// FUNCTION: LEGO1 0x1009a0f0
LegoSpline::LegoSpline()
{
	for (LegoS32 i = 0; i < sizeOfArray(m_coefficents); i++) {
		m_coefficents[i].Clear();
	}
}

// FUNCTION: LEGO1 0x1009a130
LegoSpline::~LegoSpline()
{
}

// FUNCTION: LEGO1 0x1009a140
// FUNCTION: BETA10 0x10182c2f
void LegoSpline::SetSpline(
	const Vector3& p_start,
	const Vector3& p_tangentAtStart,
	const Vector3& p_end,
	const Vector3& p_tangentAtEnd
)
{
	m_coefficents[0] = p_start;
	m_coefficents[1] = p_tangentAtStart;

	for (LegoS32 i = 0; i < 3; i++) {
		m_coefficents[2][i] = (p_end[i] - p_start[i]) * 3.0f - p_tangentAtStart[i] * 2.0f - p_tangentAtEnd[i];
		m_coefficents[3][i] = (p_start[i] - p_end[i]) * 2.0f + p_tangentAtEnd[i] + p_tangentAtStart[i];
	}
}

// FUNCTION: LEGO1 0x1009a1e0
// FUNCTION: BETA10 0x10182d61
LegoResult LegoSpline::Evaluate(float p_alpha, Matrix4& p_mat, Vector3& p_up, LegoU32 p_reverse)
{
	Vector3 position(p_mat[3]);
	Vector3 right(p_mat[0]);
	Vector3 up(p_mat[1]);
	Vector3 dir(p_mat[2]);

	if (p_alpha <= 0.001) {
		position = m_coefficents[0];
		dir = m_coefficents[1];
	}
	else if (p_alpha >= 0.999) {
		position = m_coefficents[0];
		position += m_coefficents[1];
		position += m_coefficents[2];
		position += m_coefficents[3];

		for (LegoS32 i = 0; i < 3; i++) {
			dir[i] = m_coefficents[1][i] + m_coefficents[2][i] * 2.0f + m_coefficents[3][i] * 3.0f;
		}
	}
	else {
		float alpha_squared = p_alpha * p_alpha;
		float alpha_cubed = alpha_squared * p_alpha;

		for (LegoS32 i = 0; i < 3; i++) {
			position[i] = m_coefficents[0][i] + m_coefficents[1][i] * p_alpha + m_coefficents[2][i] * alpha_squared +
						  m_coefficents[3][i] * alpha_cubed;
			dir[i] =
				m_coefficents[1][i] + m_coefficents[2][i] * p_alpha * 2.0f + m_coefficents[3][i] * alpha_squared * 3.0f;
		}
	}

	if (p_reverse) {
		dir *= -1.0f;
	}

	if (dir.Unitize() != 0) {
		return FAILURE;
	}

	right.EqualsCross(p_up, dir);
	if (right.Unitize() != 0) {
		return FAILURE;
	}

	up.EqualsCross(dir, right);
	return SUCCESS;
}
