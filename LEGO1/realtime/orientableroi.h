#ifndef ORIENTABLEROI_H
#define ORIENTABLEROI_H

#include "decomp.h"
#include "mxgeometry/mxmatrix.h"
#include "roi.h"

#include <windows.h>

// VTABLE: LEGO1 0x100dbc08
// SIZE 0xdc
class OrientableROI : public ROI {
public:
	enum {
		c_bit1 = 0x01,
		c_bit2 = 0x02
	};

	OrientableROI();

	const float* GetWorldVelocity() const override;                // vtable+0x08
	const BoundingBox& GetWorldBoundingBox() const override;       // vtable+0x0c
	const BoundingSphere& GetWorldBoundingSphere() const override; // vtable+0x10

	// FUNCTION: LEGO1 0x100a5db0
	virtual void VTable0x14() { VTable0x1c(); } // vtable+0x14

	virtual void UpdateWorldBoundingVolumes() = 0;              // vtable+0x18
	virtual void VTable0x1c();                                  // vtable+0x1c
	virtual void SetLocalTransform(const Matrix4& p_transform); // vtable+0x20
	virtual void VTable0x24(const Matrix4& p_transform);        // vtable+0x24
	virtual void UpdateWorldData(const Matrix4& p_transform);   // vtable+0x28
	virtual void UpdateWorldVelocity();                         // vtable+0x2c

	void WrappedSetLocalTransform(const Matrix4& p_transform);
	void FUN_100a46b0(const Matrix4& p_transform);
	void WrappedVTable0x24(const Matrix4& p_transform);
	void GetLocalTransform(Matrix4& p_transform);
	void FUN_100a58f0(const Matrix4& p_transform);
	void FUN_100a5a30(const Vector3& p_world_velocity);

	const Matrix4& GetLocal2World() const { return m_local2world; }
	const float* GetWorldPosition() const { return m_local2world[3]; }
	const float* GetWorldDirection() const { return m_local2world[2]; }
	const float* GetWorldUp() const { return m_local2world[1]; }
	OrientableROI* GetParentROI() const { return m_parentROI; }

	void ToggleUnknown0xd8(BOOL p_enable)
	{
		if (p_enable) {
			m_unk0xd8 |= c_bit1 | c_bit2;
		}
		else {
			m_unk0xd8 &= ~c_bit1;
		}
	}

protected:
	MxMatrix m_local2world;                 // 0x10
	BoundingBox m_world_bounding_box;       // 0x58
	BoundingBox m_unk0x80;                  // 0x80
	BoundingSphere m_world_bounding_sphere; // 0xa8
	Mx3DPointFloat m_world_velocity;        // 0xc0
	OrientableROI* m_parentROI;             // 0xd4
	undefined4 m_unk0xd8;                   // 0xd8
};

// SYNTHETIC: LEGO1 0x100a4630
// OrientableROI::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100aa2f0
// OrientableROI::~OrientableROI

#endif // ORIENTABLEROI_H
