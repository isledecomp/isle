#include "orientableroi.h"

#include "decomp.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(OrientableROI, 0xdc)

// FUNCTION: LEGO1 0x100a4420
OrientableROI::OrientableROI()
{
	FILLVEC3(m_world_bounding_box.Min(), 888888.8);
	FILLVEC3(m_world_bounding_box.Max(), -888888.8);
	ZEROVEC3(m_world_bounding_sphere.Center());
	m_world_bounding_sphere.Radius() = 0.0;
	ZEROVEC3(m_world_velocity);
	IDENTMAT4(m_local2world);

	m_unk0xd4 = NULL;
	ToggleUnknown0xd8(TRUE);
}

// Maybe an overload based on MxMatrix type
// FUNCTION: LEGO1 0x100a46a0
void OrientableROI::WrappedSetLocalTransform(const Matrix4& p_transform)
{
	SetLocalTransform(p_transform);
}

// STUB: LEGO1 0x100a46b0
void OrientableROI::FUN_100a46b0(Matrix4& p_transform)
{
	// TODO
}

// Maybe an overload based on MxMatrix type
// FUNCTION: LEGO1 0x100a5090
void OrientableROI::WrappedVTable0x24(const Matrix4& p_transform)
{
	VTable0x24(p_transform);
}

// STUB: LEGO1 0x100a50a0
void OrientableROI::GetLocalTransform(Matrix4& p_transform)
{
	// TODO
}

// FUNCTION: LEGO1 0x100a58f0
void OrientableROI::FUN_100a58f0(const Matrix4& p_transform)
{
	m_local2world = p_transform;
	ToggleUnknown0xd8(TRUE);
}

// FUNCTION: LEGO1 0x100a5910
void OrientableROI::VTable0x1c()
{
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a5930
void OrientableROI::SetLocalTransform(const Matrix4& p_transform)
{
	m_local2world = p_transform;
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a5960
void OrientableROI::VTable0x24(const Matrix4& p_transform)
{
	MxMatrix l_matrix(m_local2world);
	m_local2world.Product(p_transform, l_matrix);
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();
}

// FUNCTION: LEGO1 0x100a59b0
void OrientableROI::UpdateWorldData(const Matrix4& p_transform)
{
	MxMatrix l_matrix(m_local2world);
	m_local2world.Product(l_matrix, p_transform);
	UpdateWorldBoundingVolumes();
	UpdateWorldVelocity();

	// iterate over comps
	if (comp) {
		for (CompoundObject::iterator iter = comp->begin(); !(iter == comp->end()); iter++) {
			ROI* child = *iter;
			static_cast<OrientableROI*>(child)->UpdateWorldData(p_transform);
		}
	}
}

// FUNCTION: LEGO1 0x100a5a30
void OrientableROI::FUN_100a5a30(const Vector3& p_world_velocity)
{
	m_world_velocity = p_world_velocity;
}

// FUNCTION: LEGO1 0x100a5a50
void OrientableROI::UpdateWorldVelocity()
{
}

// FUNCTION: LEGO1 0x100a5d80
const float* OrientableROI::GetWorldVelocity() const
{
	return m_world_velocity.GetData();
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
