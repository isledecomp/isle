#ifndef ORIENTABLEROI_H
#define ORIENTABLEROI_H

#include "matrix.h"
#include "roi.h"

class OrientableROI : public ROI {
public:
	// OFFSET: LEGO1 0x100a4420
	OrientableROI()
	{
		FILLVEC3(m_world_bounding_box.Min(), 888888.8);
		FILLVEC3(m_world_bounding_box.Max(), -888888.8);
		ZEROVEC3(m_world_bounding_sphere.Center());
		m_world_bounding_sphere.Radius() = 0.0;
		ZEROVEC3(m_world_velocity);
		IDENTMAT4(m_local2world.GetMatrix());
	}
	// OFFSET: LEGO1 0x100a4630 TEMPLATE
	// OrientableROI::`scalar deleting destructor'

	virtual const Vector3& GetWorldVelocity() const;
	virtual const BoundingBox& GetWorldBoundingBox() const;
	virtual const BoundingSphere& GetWorldBoundingSphere() const;

protected:
	// vtable + 0x14
	virtual void VTable0x14() { VTable0x1c(); }
	virtual void UpdateWorldBoundingVolumes() = 0;

public:
	virtual void VTable0x1c();
	// vtable + 0x20
	virtual void SetLocalTransform(const MatrixImpl& p_transform);
	virtual void VTable0x24(const MatrixData& p_transform);
	virtual void UpdateWorldData(const MatrixData& p_transform);
	virtual void UpdateWorldVelocity();

protected:
	char m_unkc;
	MatrixData m_local2world;               // 0x10
	BoundingBox m_world_bounding_box;       // 0x58
	BoundingSphere m_world_bounding_sphere; // 0xa8
	Vector3Data m_world_velocity;           // 0xc0
	unsigned int m_unkd4;
	unsigned int m_unkd8;
};

#endif // ORIENTABLEROI_H
