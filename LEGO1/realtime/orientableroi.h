#ifndef ORIENTABLEROI_H
#define ORIENTABLEROI_H

#include "matrix.h"
#include "roi.h"

// VTABLE: LEGO1 0x100dbc08
// SIZE 0xdc
class OrientableROI : public ROI {
public:
	// FUNCTION: LEGO1 0x100a4420
	OrientableROI()
	{
		FILLVEC3(m_world_bounding_box.Min(), 888888.8);
		FILLVEC3(m_world_bounding_box.Max(), -888888.8);
		ZEROVEC3(m_world_bounding_sphere.Center());
		m_world_bounding_sphere.Radius() = 0.0;
		ZEROVEC3(m_world_velocity);
		IDENTMAT4(m_local2world.GetMatrix());
	}

	virtual const Vector3& GetWorldVelocity() const override;              // vtable+0x8
	virtual const BoundingBox& GetWorldBoundingBox() const override;       // vtable+0xc
	virtual const BoundingSphere& GetWorldBoundingSphere() const override; // vtable+0x10
	// FUNCTION: LEGO1 0x100a5db0
	virtual void VTable0x14() { VTable0x1c(); }                     // vtable+0x14
	virtual void UpdateWorldBoundingVolumes() = 0;                  // vtable+0x18
	virtual void VTable0x1c();                                      // vtable+0x1c
	virtual void SetLocalTransform(const Matrix4Impl& p_transform); // vtable+0x20
	virtual void VTable0x24(const Matrix4Data& p_transform);        // vtable+0x24
	virtual void UpdateWorldData(const Matrix4Data& p_transform);   // vtable+0x28
	virtual void UpdateWorldVelocity();                             // vtable+0x2c

	// SYNTHETIC: LEGO1 0x100a4630
	// OrientableROI::`scalar deleting destructor'

protected:
	char m_unk0xc;                          // 0xc
	Matrix4Data m_local2world;              // 0x10
	BoundingBox m_world_bounding_box;       // 0x58
	BoundingSphere m_world_bounding_sphere; // 0xa8
	Vector3Data m_world_velocity;           // 0xc0
	unsigned int m_unk0xd4;                 // 0xd4
	unsigned int m_unk0xd8;                 // 0xd8
};

#endif // ORIENTABLEROI_H
