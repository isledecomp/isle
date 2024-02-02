#ifndef VIEWMANAGER_H
#define VIEWMANAGER_H

#include "viewroi.h"

// VTABLE: LEGO1 0x100dbd88
// SIZE 0x1bc
class ViewManager {
public:
	ViewManager(Tgl::Renderer* pRenderer, Tgl::Group* scene, const OrientableROI* point_of_view);
	virtual ~ViewManager();

	void RemoveAll(ViewROI*);

	void SetPOVSource(const OrientableROI* point_of_view);
	void SetResolution(int width, int height);
	void SetFrustrum(float fov, float front, float back);
	void Update(float p_previousRenderTime, float p_und2);

	// SYNTHETIC: LEGO1 0x100a6000
	// ViewManager::`scalar deleting destructor'

	inline void AddToUnknown0x08(ViewROI* p_roi) { m_unk0x08.push_back(p_roi); }

private:
	undefined4 m_unk0x04;     // 0x04
	CompoundObject m_unk0x08; // 0x08
	undefined m_pad[0x1c8];   // 0x14
};

// TEMPLATE: LEGO1 0x10022030
// list<ROI *,allocator<ROI *> >::insert

#endif // VIEWMANAGER_H
