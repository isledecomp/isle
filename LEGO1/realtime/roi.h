#ifndef ROI_H
#define ROI_H

// ROI stands for Real-time Object Instance.

#include "compat.h"
#include "lodlist.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxstl/stlcompat.h"
#include "realtime/realtime.h"

/*
 * A simple bounding box object with Min and Max accessor methods.
 */
// SIZE 0x28
class BoundingBox {
public:
	const Vector3& Min() const { return min; }
	Vector3& Min() { return min; }
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
	const Vector3& Center() const { return center; }
	Vector3& Center() { return center; }
	const float& Radius() const { return radius; }
	float& Radius() { return radius; }

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
		m_unk0x0c = 1;
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
	const CompoundObject* GetComp() const { return comp; }

	inline undefined GetUnknown0x0c() { return m_unk0x0c; }
	inline void SetUnknown0x0c(undefined p_unk0x0c) { m_unk0x0c = p_unk0x0c; }

	// SYNTHETIC: LEGO1 0x100a5d60
	// ROI::`scalar deleting destructor'

protected:
	CompoundObject* comp; // 0x04
	LODListBase* lods;    // 0x08
	undefined m_unk0x0c;  // 0x0c
};

// TEMPLATE: LEGO1 0x10084930
// list<ROI *,allocator<ROI *> >::~list<ROI *,allocator<ROI *> >

// SYNTHETIC: LEGO1 0x100a5d50
// ROI::~ROI

#endif // ROI_H
