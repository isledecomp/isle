#ifndef __LEGOSPLINE_H
#define __LEGOSPLINE_H

#include "legotypes.h"
#include "mxgeometry/mxgeometry3d.h"

class Matrix4;

// SIZE 0x50
class LegoSpline {
public:
	LegoSpline();
	~LegoSpline();

	void SetSpline(
		const Vector3& p_start,
		const Vector3& p_tangentAtStart,
		const Vector3& p_end,
		const Vector3& p_tangentAtEnd
	);
	LegoResult Evaluate(float p_alpha, Matrix4& p_mat, Vector3& p_v, LegoU32 p_reverse);

private:
	Mx3DPointFloat m_coefficents[4]; // 0x00
};

#endif // __LEGOSPLINE_H
