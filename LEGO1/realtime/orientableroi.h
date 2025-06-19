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
	// FUNCTION: BETA10 0x101687d0
	virtual void WrappedUpdateWorldData() { UpdateWorldData(); } // vtable+0x14

	virtual void UpdateWorldBoundingVolumes() = 0;                                    // vtable+0x18
	virtual void UpdateWorldData();                                                   // vtable+0x1c
	virtual void SetLocal2WorldWithWorldDataUpdate(const Matrix4& p_local2world);     // vtable+0x20
	virtual void UpdateWorldDataWithTransform(const Matrix4& p_transform);            // vtable+0x24
	virtual void UpdateWorldDataWithTransformAndChildren(const Matrix4& p_transform); // vtable+0x28
	virtual void UpdateWorldVelocity();                                               // vtable+0x2c

	void WrappedSetLocal2WorldWithWorldDataUpdate(const Matrix4& p_local2world);
	void UpdateTransformationRelativeToParent(const Matrix4& p_transform);
	void WrappedUpdateWorldDataWithTransform(const Matrix4& p_transform);
	void GetLocalTransform(Matrix4& p_transform);
	void SetLocal2World(const Matrix4& p_local2world);
	void SetWorldVelocity(const Vector3& p_world_velocity);

	// FUNCTION: BETA10 0x1000fbf0
	const Matrix4& GetLocal2World() const { return m_local2world; }

	// FUNCTION: BETA10 0x10011750
	const float* GetWorldPosition() const { return m_local2world[3]; }

	// FUNCTION: BETA10 0x10011780
	const float* GetWorldDirection() const { return m_local2world[2]; }

	// FUNCTION: BETA10 0x1004aa70
	const float* GetWorldUp() const { return m_local2world[1]; }

	// FUNCTION: BETA10 0x10070380
	OrientableROI* GetParentROI() const { return m_parentROI; }

	void SetParentROI(OrientableROI* p_parentROI) { m_parentROI = p_parentROI; }

	// FUNCTION: BETA10 0x10168800
	void SetNeedsWorldDataUpdate(BOOL p_needsWorldDataUpdate)
	{
		if (p_needsWorldDataUpdate) {
			m_unk0xd8 |= c_bit1 | c_bit2;
		}
		else {
			m_unk0xd8 &= ~c_bit1;
		}
	}

protected:
	MxMatrix m_local2world;                 // 0x10
	BoundingBox m_world_bounding_box;       // 0x58
	BoundingBox m_bounding_box;             // 0x80
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
