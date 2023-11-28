#include "orientableroi.h"

#include "../decomp.h"

DECOMP_SIZE_ASSERT(OrientableROI, 0xdc)

// FUNCTION: LEGO1 0x100a5910
void OrientableROI::VTable0x1c()
{
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a5930
void OrientableROI::SetLocalTransform(const Matrix4Impl& p_transform)
{
	reinterpret_cast<Matrix4Impl&>(m_local2world) = p_transform;
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a5960
void OrientableROI::VTable0x24(const Matrix4Data& p_transform)
{
	Matrix4Data l_matrix(m_local2world);
	m_local2world.EqualsMxProduct(&p_transform, &l_matrix);
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a59b0
void OrientableROI::UpdateWorldData(const Matrix4Data& p_transform)
{
	Matrix4Data l_matrix(m_local2world);
	m_local2world.EqualsMxProduct(&l_matrix, &p_transform);
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();

	// iterate over comps
	if (m_comp)
		for (CompoundObject::iterator iter = m_comp->begin(); !(iter == m_comp->end()); iter++) {
			ROI* child = *iter;
			static_cast<OrientableROI*>(child)->UpdateWorldData(p_transform);
		}
}

// FUNCTION: LEGO1 0x100a5a50
void OrientableROI::UpdateWorldVelocity()
{
}

// FUNCTION: LEGO1 0x100a5d80
const Vector3& OrientableROI::GetWorldVelocity() const
{
	return (Vector3&) *m_world_velocity.GetData();
}

// FUNCTION: LEGO1 0x100a5d90
const BoundingBox& OrientableROI::GetWorldBoundingBox() const
{
	return m_world_bounding_box;
}

// FUNCTION: LEGO1 0x100a5da0
const BoundingSphere& OrientableROI::GetWorldBoundingSphere() const
{
	return m_world_bounding_sphere;
}
