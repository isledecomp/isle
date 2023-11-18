#ifndef ROI_H
#define ROI_H

#include "../compat.h"
#include "../mxstl.h"
#include "../realtime/realtime.h"
#include "lodlist.h"
#include "vector.h"

/*
 * A simple bounding box object with Min and Max accessor methods.
 */
class BoundingBox {
public:
	const Vector3Data& Min() const { return min; }
	Vector3Data& Min() { return min; }
	const Vector3Data& Max() const { return max; }
	Vector3Data& Max() { return max; }

private:
	Vector3Data min;
	Vector3Data max;
	Vector3Data m_unk28;
	Vector3Data m_unk3c;
};

/*
 * A simple bounding sphere object with center and radius accessor methods.
 */
class BoundingSphere {
public:
	const Vector3Data& Center() const { return center; }
	Vector3Data& Center() { return center; }
	const float& Radius() const { return radius; }
	float& Radius() { return radius; }

private:
	Vector3Data center;
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
	virtual float Cost(float pixels_covered) const = 0;
	virtual float AveragePolyArea() const = 0;
	virtual int NVerts() const = 0;
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

class ROI {
public:
	ROI()
	{
		m_comp = 0;
		m_lods = 0;
	}
	virtual ~ROI()
	{
		// if derived class set the comp and lods, it should delete them
		assert(!m_comp);
		assert(!m_lods);
	}
	virtual float IntrinsicImportance() const = 0;
	virtual const Vector3& GetWorldVelocity() const = 0;
	virtual const BoundingBox& GetWorldBoundingBox() const = 0;
	virtual const BoundingSphere& GetWorldBoundingSphere() const = 0;

	const LODListBase* GetLODs() const { return m_lods; }
	const LODObject* GetLOD(int i) const
	{
		assert(m_lods);
		return (*m_lods)[i];
	}
	int GetLODCount() const { return m_lods ? m_lods->Size() : 0; }
	const CompoundObject* GetComp() const { return m_comp; }

protected:
	CompoundObject* m_comp;
	LODListBase* m_lods;
};
#endif // ROI_H
