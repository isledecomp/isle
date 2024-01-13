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
	const Mx3DPointFloat& Min() const { return min; }
	Mx3DPointFloat& Min() { return min; }
	const Mx3DPointFloat& Max() const { return max; }
	Mx3DPointFloat& Max() { return max; }

private:
	Mx3DPointFloat min;
	Mx3DPointFloat max;
};

/*
 * A simple bounding sphere object with center and radius accessor methods.
 */
// SIZE 0x18
class BoundingSphere {
public:
	const Mx3DPointFloat& Center() const { return center; }
	Mx3DPointFloat& Center() { return center; }
	const float& Radius() const { return radius; }
	float& Radius() { return radius; }

private:
	Mx3DPointFloat center;
	float radius;
};

/*
 * Abstract base class representing a single LOD version of
 * a geometric object.
 */
class LODObject {
public:
	// LODObject();
	virtual ~LODObject() {}
	virtual float Cost(float pixels_covered) const = 0; // vtable+0x4
	virtual float AveragePolyArea() const = 0;          // vtable+0x8
	virtual int NVerts() const = 0;                     // vtable+0xc
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
		m_comp = 0;
		m_lods = 0;
		m_unk0xc = 1;
	}
	virtual ~ROI()
	{
		// if derived class set the comp and lods, it should delete them
		assert(!m_comp);
		assert(!m_lods);
	}
	virtual float IntrinsicImportance() const = 0;                    // vtable+0x4
	virtual const float* GetWorldVelocity() const = 0;                // vtable+0x8
	virtual const BoundingBox& GetWorldBoundingBox() const = 0;       // vtable+0xc
	virtual const BoundingSphere& GetWorldBoundingSphere() const = 0; // vtable+0x10

	const LODListBase* GetLODs() const { return m_lods; }
	const LODObject* GetLOD(int i) const
	{
		assert(m_lods);
		return (*m_lods)[i];
	}
	int GetLODCount() const { return m_lods ? m_lods->Size() : 0; }
	const CompoundObject* GetComp() const { return m_comp; }

protected:
	CompoundObject* m_comp; // 0x4
	LODListBase* m_lods;    // 0x8
	undefined m_unk0xc;     // 0xc
};
#endif // ROI_H
