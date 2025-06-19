#ifndef ROI_H
#define ROI_H

// ROI stands for Real-time Object Instance.

#include "compat.h"
#include "decomp.h"
#include "lodlist.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxstl/stlcompat.h"

/*
 * A simple bounding box object with Min and Max accessor methods.
 */
// SIZE 0x28
class BoundingBox {
public:
	// The BETA10 matches may reference the wrong version

	// FUNCTION: BETA10 0x1004a7a0
	const Vector3& Min() const { return min; }
	Vector3& Min() { return min; }
	// FUNCTION: BETA10 0x1004a7c0
	const Vector3& Max() const { return max; }
	Vector3& Max() { return max; }

private:
	Mx3DPointFloat min; // 0x00
	Mx3DPointFloat max; // 0x14
};

/*
 * A simple bounding sphere object with center and radius accessor methods.
 */
// SIZE 0x18
class BoundingSphere {
public:
	// The BETA10 matches may reference the wrong version

	// FUNCTION: BETA10 0x1001fac0
	const Vector3& Center() const { return center; }

	// FUNCTION: BETA10 0x100d55a0
	Vector3& Center() { return center; }

	// FUNCTION: BETA10 0x1001fd30
	const float& Radius() const { return radius; }

	// FUNCTION: BETA10 0x1001fae0
	float& Radius() { return radius; }

	// SYNTHETIC: BETA10 0x1001fb90
	// BoundingSphere::operator=

	// SYNTHETIC: BETA10 0x1001fc50
	// BoundingSphere::BoundingSphere

private:
	Mx3DPointFloat center; // 0x00
	float radius;          // 0x14
};

/*
 * Abstract base class representing a single LOD version of
 * a geometric object.
 */
// VTABLE: LEGO1 0x100dbd90
// SIZE 0x04
class LODObject {
public:
	// LODObject();

	// FUNCTION: LEGO1 0x100a6f00
	virtual ~LODObject() {}

	virtual double AveragePolyArea() const = 0; // vtable+0x04
	virtual int NVerts() const = 0;             // vtable+0x08
	virtual int NumPolys() const = 0;           // vtable+0x0c
	virtual float VTable0x10() = 0;             // vtable+0x10

	// SYNTHETIC: LEGO1 0x100a6f10
	// LODObject::`scalar deleting destructor'
};

/*
 * A CompoundObject is simply a set of ROI objects which
 * all together represent a single object with sub-parts.
 */
class ROI;
// typedef std::set<ROI*, std::less<const ROI*> > CompoundObject;
typedef list<ROI*> CompoundObject;

/*
 * A ROIList is a list of ROI objects.
 */
typedef vector<const ROI*> ROIList;

/*
 * A simple list of integers.
 * Returned by RealtimeView::SelectLODs as indices into an ROIList.
 */
typedef vector<int> IntList;

// VTABLE: LEGO1 0x100dbc38
// SIZE 0x10
class ROI {
public:
	ROI()
	{
		comp = 0;
		lods = 0;
		m_visible = true;
	}
	virtual ~ROI()
	{
		// if derived class set the comp and lods, it should delete them
		assert(!comp);
		assert(!lods);
	}
	virtual float IntrinsicImportance() const = 0;                    // vtable+0x04
	virtual const float* GetWorldVelocity() const = 0;                // vtable+0x08
	virtual const BoundingBox& GetWorldBoundingBox() const = 0;       // vtable+0x0c
	virtual const BoundingSphere& GetWorldBoundingSphere() const = 0; // vtable+0x10

	const LODListBase* GetLODs() const { return lods; }
	const LODObject* GetLOD(int i) const
	{
		assert(lods);
		return (*lods)[i];
	}
	int GetLODCount() const { return lods ? lods->Size() : 0; }

	// FUNCTION: BETA10 0x10027110
	const CompoundObject* GetComp() const { return comp; }

	// FUNCTION: BETA10 0x10049e10
	unsigned char GetVisibility() { return m_visible; }

	// FUNCTION: BETA10 0x10011720
	void SetVisibility(unsigned char p_visible) { m_visible = p_visible; }

	// SYNTHETIC: LEGO1 0x100a5d60
	// ROI::`scalar deleting destructor'

protected:
	CompoundObject* comp;    // 0x04
	LODListBase* lods;       // 0x08
	unsigned char m_visible; // 0x0c
};

// TEMPLATE: LEGO1 0x10084930
// list<ROI *,allocator<ROI *> >::~list<ROI *,allocator<ROI *> >

// SYNTHETIC: LEGO1 0x100a5d50
// SYNTHETIC: BETA10 0x101686a0
// ROI::~ROI

#endif // ROI_H
