#ifndef REALTIME_H
#define REALTIME_H

#include "matrix.h"
#include "roi.h"

#define NORMVEC3(dst, src)                                                                                             \
	{                                                                                                                  \
		double len = sqrt(NORMSQRD3(src));                                                                             \
		VDS3(dst, src, len);                                                                                           \
	}

void CalcLocalTransform(const Vector3& p_posVec, const Vector3& p_dirVec, const Vector3& p_upVec, Matrix4& p_outMatrix);

// utility to help derived ROI classes implement
// update_world_bounding_volumes() using a modelling sphere
void CalcWorldBoundingVolumes(const BoundingSphere& modelling_sphere, const Matrix4& local2world, BoundingBox&, BoundingSphere&);

#endif // REALTIME_H
