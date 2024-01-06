#ifndef LEGO3DVIEW_H
#define LEGO3DVIEW_H

#include "3dmanager/tglsurface.h"
#include "decomp.h"
#include "mxtypes.h"
#include "viewmanager/viewmanager.h"

class LegoROI;

// VTABLE: LEGO1 0x100dbf78
// SIZE 0xa8
class Lego3DView {
public:
	Lego3DView();
	virtual ~Lego3DView();

	BOOL Create(TglSurface::CreateStruct& p_createStruct, Tgl::Renderer* p_renderer);
	LegoROI* PickROI(MxLong p_a, MxLong p_b);
	void FUN_100ab100(LegoROI* p_roi);
	void FUN_100ab1b0(LegoROI* p_roi);

	inline ViewManager* GetViewManager() { return this->m_viewManager; }
	inline Tgl::Device* GetDevice() { return this->m_device; }
	inline Tgl::View* GetView() { return this->m_view; }

private:
	// TODO: all of these fields are in various base classes
	undefined4 m_unk0x4;        // 0x04
	Tgl::Renderer* m_renderer;  // 0x08
	Tgl::Device* m_device;      // 0x0c
	Tgl::View* m_view;          // 0x10
	undefined m_unk0x14[0x74];  // 0x14
	ViewManager* m_viewManager; // 0x88
	undefined m_unk0x8c[0x1c];  // 0x8c
};

// SYNTHETIC: LEGO1 0x100aaf10
// Lego3DView::`scalar deleting destructor'

#endif // LEGO3DVIEW_H
