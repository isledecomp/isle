#ifndef REALTIME_H
#define REALTIME_H

#include "matrix.h"

#define NORMVEC3(dst, src)                                                                                             \
	{                                                                                                                  \
		double len = sqrt(NORMSQRD3(src));                                                                             \
		VDS3(dst, src, len);                                                                                           \
	}

void CalcLocalTransform(const Vector3& p_posVec, const Vector3& p_dirVec, const Vector3& p_upVec, Matrix4& p_outMatrix);

#endif // REALTIME_H
