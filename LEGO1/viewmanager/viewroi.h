#ifndef VIEWROI_H
#define VIEWROI_H

#include "decomp.h"
#include "realtime/orientableroi.h"
#include "tgl/tgl.h"
#include "viewlodlist.h"

/*
	ViewROI objects represent view objects, collections of view objects,
	etc. Basically, anything which can be placed in a scene and manipilated
	by the view manager is a ViewROI.
*/

// VTABLE: LEGO1 0x100dbe70
// VTABLE: BETA10 0x101c3908
// SIZE 0xe4
class ViewROI : public OrientableROI {
public:
	enum {
		c_lodLevelUnset = -1,
		c_lodLevelInvisible = -2,
	};

	// FUNCTION: BETA10 0x1018c5e0
	ViewROI(Tgl::Renderer* pRenderer, ViewLODList* lodList)
	{
		SetLODList(lodList);
		geometry = pRenderer->CreateGroup();
		m_lodLevel = c_lodLevelUnset;
	}

	// FUNCTION: LEGO1 0x100a9e20
	// FUNCTION: BETA10 0x1018c680
	~ViewROI() override
	{
		// SetLODList() will decrease refCount of LODList
		SetLODList(0);
		delete geometry;
	}

	// FUNCTION: BETA10 0x1007b540
	void SetLODList(ViewLODList* lodList)
	{
		// ??? inherently type unsafe - kind of... because, now, ROI
		//     does not expose SetLODs() ...
		// solution: create pure virtual LODListBase* ROI::GetLODList()
		// and let derived ROI classes hold the LODList

		if (lods) {
			reinterpret_cast<ViewLODList*>(lods)->Release();
		}

		lods = lodList;

		if (lods) {
			reinterpret_cast<ViewLODList*>(lods)->AddRef();
		}
	}

	float IntrinsicImportance() const override;                                  // vtable+0x04
	void UpdateWorldData() override;                                             // vtable+0x1c
	void SetLocal2WorldWithWorldDataUpdate(const Matrix4& p_transform) override; // vtable+0x20
	void UpdateWorldDataWithTransform(const Matrix4& p_transform) override;      // vtable+0x24
	virtual Tgl::Group* GetGeometry();                                           // vtable+0x30
	virtual const Tgl::Group* GetGeometry() const;                               // vtable+0x34

	int GetLodLevel() { return m_lodLevel; }
	void SetLodLevel(int p_lodLevel) { m_lodLevel = p_lodLevel; }

	static unsigned char SetLightSupport(unsigned char p_lightSupport);

protected:
	void UpdateWorldDataWithTransformAndChildren(const Matrix4& parent2world) override; // vtable+0x28

	void SetGeometryTransformation();

	Tgl::Group* geometry; // 0xdc
	int m_lodLevel;       // 0xe0
};

// SYNTHETIC: LEGO1 0x100aa250
// ViewROI::`scalar deleting destructor'

#endif // VIEWROI_H
