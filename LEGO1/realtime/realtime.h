#ifndef REALTIME_H
#define REALTIME_H

#include "../mxmatrix.h"

#define NORMVEC3(dst, src)                                                                                             \
	{                                                                                                                  \
		MxDouble len = sqrt(NORMSQRD3(src));                                                                           \
		VDS3(dst, src, len);                                                                                           \
	}

void CalcLocalTransform(
	const MxVector3& p_posVec,
	const MxVector3& p_dirVec,
	const MxVector3& p_upVec,
	MxMatrix& p_outMatrix
);

#endif // REALTIME_H
