#include "realtime.h"

#include <vec.h>

// FUNCTION: LEGO1 0x100a5b40
void CalcLocalTransform(const Vector3& p_posVec, const Vector3& p_dirVec, const Vector3& p_upVec, Matrix4& p_outMatrix)
{
	float x_axis[3], y_axis[3], z_axis[3];

	NORMVEC3(z_axis, p_dirVec);
	NORMVEC3(y_axis, p_upVec)
	VXV3(x_axis, y_axis, z_axis);
	NORMVEC3(x_axis, x_axis);
	VXV3(y_axis, z_axis, x_axis);
	NORMVEC3(y_axis, y_axis);
	SET4from3(p_outMatrix[0], x_axis, 0);
	SET4from3(p_outMatrix[1], y_axis, 0);
	SET4from3(p_outMatrix[2], z_axis, 0);
	SET4from3(p_outMatrix[3], p_posVec, 1);
}
