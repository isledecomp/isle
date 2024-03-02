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
	width = 0.0;
	height = 0.0;
	view_angle = 0.0;
	pov.SetIdentity();
	front = 0.0;
	back = 0.0;

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

// FUNCTION: LEGO1 0x100a6d50
void ViewManager::SetResolution(int width, int height)
{
	flags |= c_bit3;
	this->width = width;
	this->height = height;
}

// FUNCTION: LEGO1 0x100a6d70
void ViewManager::SetFrustrum(float fov, float front, float back)
{
	this->front = front;
	this->back = back;
	flags |= c_bit3;
	view_angle = fov * 0.017453292519944444;
}

// FUNCTION: LEGO1 0x100a6da0
void ViewManager::SetPOVSource(const OrientableROI* point_of_view)
{
	if (point_of_view != NULL) {
		pov = point_of_view->GetLocal2World();
		flags |= c_bit2;
	}
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
