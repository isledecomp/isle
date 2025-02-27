#ifndef __LEGOUNKNOWN_H
#define __LEGOUNKNOWN_H

#include "legotypes.h"
#include "mxgeometry/mxgeometry3d.h"

class Matrix4;

// SIZE 0x50
class LegoUnknown {
public:
	LegoUnknown();
	~LegoUnknown();

	void FUN_1009a140(
		const Vector3& p_point1,
		const Vector3& p_point2,
		const Vector3& p_point3,
		const Vector3& p_point4
	);
	LegoResult FUN_1009a1e0(float p_f1, Matrix4& p_mat, Vector3& p_v, LegoU32 p_und);

private:
	Mx3DPointFloat m_unk0x00[4]; // 0x00
};

#endif // __LEGOUNKNOWN_H
