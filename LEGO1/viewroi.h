#ifndef VIEWROI_H
#define VIEWROI_H

#include "orientableroi.h"
#include "tgl/tgl.h"
#include "viewlodlist.h"

/*
	ViewROI objects represent view objects, collections of view objects,
	etc. Basically, anything which can be placed in a scene and manipilated
	by the view manager is a ViewROI.
*/
class ViewROI : public OrientableROI {
public:
	inline ViewROI(Tgl::Renderer* pRenderer, ViewLODList* lodList)
	{
		SetLODList(lodList);
		geometry = pRenderer->CreateGroup();
	}
	inline ~ViewROI();
	inline void SetLODList(ViewLODList* lodList)
	{
		// ??? inherently type unsafe - kind of... because, now, ROI
		//     does not expose SetLODs() ...
		// solution: create pure virtual LODListBase* ROI::GetLODList()
		// and let derived ROI classes hold the LODList

		if (m_lods) {
			reinterpret_cast<ViewLODList*>(m_lods)->Release();
		}

		m_lods = lodList;

		if (m_lods) {
			reinterpret_cast<ViewLODList*>(m_lods)->AddRef();
		}
	}
	virtual float IntrinsicImportance() const;
	virtual Tgl::Group* GetGeometry();
	virtual const Tgl::Group* GetGeometry() const;

protected:
	Tgl::Group* geometry;
	void UpdateWorldData(const MxMatrixData& parent2world);
};

#endif // VIEWROI_H
