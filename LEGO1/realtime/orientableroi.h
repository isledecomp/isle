#ifndef ORIENTABLEROI_H
#define ORIENTABLEROI_H

#include "decomp.h"
#include "mxgeometry/mxmatrix.h"
#include "roi.h"

// VTABLE: LEGO1 0x100dbc08
// SIZE 0xdc
class OrientableROI : public ROI {
public:
	enum {
		Flag_Bit1 = 0x01,
		Flag_Bit2 = 0x02
	};

	OrientableROI();

	virtual const float* GetWorldVelocity() const override;                // vtable+0x8
	virtual const BoundingBox& GetWorldBoundingBox() const override;       // vtable+0xc
	virtual const BoundingSphere& GetWorldBoundingSphere() const override; // vtable+0x10
	// FUNCTION: LEGO1 0x100a5db0
	virtual void VTable0x14() { VTable0x1c(); }                 // vtable+0x14
	virtual void UpdateWorldBoundingVolumes() = 0;              // vtable+0x18
	virtual void VTable0x1c();                                  // vtable+0x1c
	virtual void SetLocalTransform(const Matrix4& p_transform); // vtable+0x20
	virtual void VTable0x24(const MxMatrix& p_transform);       // vtable+0x24
	virtual void UpdateWorldData(const MxMatrix& p_transform);  // vtable+0x28
	virtual void UpdateWorldVelocity();                         // vtable+0x2c

	const float* GetWorldPosition() const { return m_local2world[3]; }
	const float* GetWorldDirection() const { return m_local2world[2]; }
	const float* GetWorldUp() const { return m_local2world[1]; }

	// SYNTHETIC: LEGO1 0x100a4630
	// OrientableROI::`scalar deleting destructor'

protected:
	MxMatrix m_local2world;           // 0x10
	BoundingBox m_world_bounding_box; // 0x58

	// Unclear whether the following vectors are:
	// 1) Part of m_world_bounding_box;
	// 2) A second BoundingBox;
	// 3) Standalone vectors

	Mx3DPointFloat m_unk0x80;               // 0x80
	Mx3DPointFloat m_unk0x94;               // 0x94
	BoundingSphere m_world_bounding_sphere; // 0xa8
	Mx3DPointFloat m_world_velocity;        // 0xc0
	undefined4 m_unk0xd4;                   // 0xd4
	undefined4 m_unk0xd8;                   // 0xd8
};

#endif // ORIENTABLEROI_H
