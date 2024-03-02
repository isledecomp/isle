#include "viewmanager.h"

#include "tgl/d3drm/impl.h"

DECOMP_SIZE_ASSERT(ViewManager, 0x1bc)

inline undefined4 SetD3DRM(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer);
inline undefined4 SetFrame(IDirect3DRMFrame2*& frame, Tgl::Group* scene);

// FUNCTION: LEGO1 0x100a5eb0
ViewManager::ViewManager(Tgl::Renderer* pRenderer, Tgl::Group* scene, const OrientableROI* point_of_view)
	: scene(scene), flags(c_bit1 | c_bit2 | c_bit3 | c_bit4)
{
	SetPOVSource(point_of_view);
	unk0x28 = 0.09;
	SetD3DRM(d3drm, pRenderer);
	SetFrame(frame, scene);
	unk0x34 = 0.0;
	unk0x38 = 0.0;
	unk0x3c = 0.0;
	unk0x40.SetIdentity();
	unk0x88 = 0.0;
	unk0x8c = 0.0;

	memset(unk0xf0, 0, sizeof(unk0xf0));
	seconds_allowed = 1.0;
}

// FUNCTION: LEGO1 0x100a60c0
ViewManager::~ViewManager()
{
	SetPOVSource(NULL);
}

// STUB: LEGO1 0x100a64d0
void ViewManager::RemoveAll(ViewROI*)
{
	// TODO
}

// STUB: LEGO1 0x100a6930
void ViewManager::Update(float p_previousRenderTime, float p_und2)
{
	// TODO
}

// STUB: LEGO1 0x100a6d50
void ViewManager::SetResolution(int width, int height)
{
	// TODO
}

// STUB: LEGO1 0x100a6d70
void ViewManager::SetFrustrum(float fov, float front, float back)
{
	// TODO
}

// STUB: LEGO1 0x100a6da0
void ViewManager::SetPOVSource(const OrientableROI* point_of_view)
{
	// TODO
}

inline undefined4 SetD3DRM(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer)
{
	d3drm = ((TglImpl::RendererImpl*) pRenderer)->ImplementationData();
	return 0;
}

inline undefined4 SetFrame(IDirect3DRMFrame2*& frame, Tgl::Group* scene)
{
	frame = ((TglImpl::GroupImpl*) scene)->ImplementationData();
	return 0;
}
