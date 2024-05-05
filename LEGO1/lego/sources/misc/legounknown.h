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

	void FUN_1009a140(Vector3& p_point1, Vector3& p_point2, Vector3& p_point3, Vector3& p_point4);
	LegoResult FUN_1009a1e0(float, Matrix4&, Vector3&, LegoU32);

private:
	Mx3DPointFloat m_unk0x00[4]; // 0x00
};

#endif // __LEGOUNKNOWN_H
