#ifndef REALTIME_H
#define REALTIME_H

#include "matrix.h"

#define NORMVEC3(dst, src)                                                                                             \
	{                                                                                                                  \
		double len = sqrt(NORMSQRD3(src));                                                                             \
		VDS3(dst, src, len);                                                                                           \
	}

void CalcLocalTransform(
	const Vector3Impl& p_posVec,
	const Vector3Impl& p_dirVec,
	const Vector3Impl& p_upVec,
	MatrixImpl& p_outMatrix
);

#endif // REALTIME_H
