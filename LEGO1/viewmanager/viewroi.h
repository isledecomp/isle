#ifndef VIEWROI_H
#define VIEWROI_H

#include "decomp.h"
// clang-format off
// MSVC 4.20 lays out .rdata in declaration order of internal-linkage consts, so
// the order these two are parsed decides where Tgl's Pi lands relative to
// realtime's constants. 1997 parsed tgl first; alphabetising inverts it.
#include "tgl/tgl.h"
#include "realtime/orientableroi.h"
// clang-format on
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
		c_tokenUnset = -1,
		c_tokenInvisible = -2,
	};

	// FUNCTION: BETA10 0x1018c5e0
	ViewROI(Tgl::Renderer* pRenderer, ViewLODList* lodList)
	{
		SetLODList(lodList);
		geometry = pRenderer->CreateGroup();
		m_token = c_tokenUnset;
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

	int GetToken() { return m_token; }
	void SetToken(int p_lodLevel) { m_token = p_lodLevel; }

	static unsigned char SetLightSupport(unsigned char p_lightSupport);

protected:
	void UpdateWorldDataWithTransformAndChildren(const Matrix4& parent2world) override; // vtable+0x28

	void SetGeometryTransformation();

	Tgl::Group* geometry; // 0xdc
	int m_token;       // 0xe0
};

// SYNTHETIC: LEGO1 0x100aa250
// ViewROI::`scalar deleting destructor'

#endif // VIEWROI_H
