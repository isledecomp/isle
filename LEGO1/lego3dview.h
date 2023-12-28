#ifndef LEGO3DVIEW_H
#define LEGO3DVIEW_H

#include "mxtypes.h"
#include "tgl/d3drm/impl.h"
#include "viewmanager/viewmanager.h"

class LegoROI;

class Lego3DView {
public:
	inline ViewManager* GetViewManager() { return this->m_viewManager; }
	inline TglImpl::ViewImpl* GetViewPort() { return this->m_viewPort; }
	LegoROI* PickROI(MxLong p_a, MxLong p_b);

private:
	// TODO: all of these fields are in various base classes
	undefined4 m_vtable;                 // 0x0 (TODO: remove once virtual function added)
	undefined4 m_unk0x4;                 // 0x4
	TglImpl::RendererImpl* m_renderImpl; // 0x8
	TglImpl::DeviceImpl* m_deviceImpl;   // 0xc
	TglImpl::ViewImpl* m_viewPort;       // 0x10
	char m_pad[0x78];                    // 0x14
	ViewManager* m_viewManager;          // 0x88
};

#endif // LEGO3DVIEW_H
