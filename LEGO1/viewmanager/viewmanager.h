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

	inline CompoundObject& GetUnknown0x08() { return m_unk0x08; }

private:
	CompoundObject m_unk0x08; // 0x08
	undefined m_pad[0x1cc];   // 0x14
};

#endif // VIEWMANAGER_H
