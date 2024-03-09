#include "viewmanager.h"

#include "tgl/d3drm/impl.h"
#include "viewlod.h"

DECOMP_SIZE_ASSERT(ViewManager, 0x1bc)

// GLOBAL: LEGO1 0x100dbcd8
int g_unk0x100dbcd8[18] = {0, 1, 5, 6, 2, 3, 3, 0, 4, 1, 2, 6, 0, 3, 2, 4, 5, 6};

inline undefined4 GetD3DRM(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer);
inline undefined4 GetFrame(IDirect3DRMFrame2*& frame, Tgl::Group* scene);

// FUNCTION: LEGO1 0x100a5eb0
ViewManager::ViewManager(Tgl::Renderer* pRenderer, Tgl::Group* scene, const OrientableROI* point_of_view)
	: scene(scene), flags(c_bit1 | c_bit2 | c_bit3 | c_bit4)
{
	SetPOVSource(point_of_view);
	unk0x28 = 0.09;
	GetD3DRM(d3drm, pRenderer);
	GetFrame(frame, scene);
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

// FUNCTION: LEGO1 0x100a6410
void ViewManager::Remove(ViewROI* p_roi)
{
	for (CompoundObject::iterator it = rois.begin(); it != rois.end(); it++) {
		if (*it == p_roi) {
			rois.erase(it);

			if (p_roi->GetUnknown0xe0() >= 0) {
				FUN_100a66a0(p_roi);
			}

			const CompoundObject* comp = p_roi->GetComp();

			if (comp != NULL) {
				for (CompoundObject::const_iterator it = comp->begin(); !(it == comp->end()); it++) {
					if (((ViewROI*) *it)->GetUnknown0xe0() >= 0) {
						FUN_100a66a0((ViewROI*) *it);
					}
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x100a64d0
void ViewManager::RemoveAll(ViewROI* p_roi)
{
	if (p_roi == NULL) {
		for (CompoundObject::iterator it = rois.begin(); it != rois.end(); it++) {
			RemoveAll((ViewROI*) *it);
		}

		rois.erase(rois.begin(), rois.end());
	}
	else {
		if (p_roi->GetUnknown0xe0() >= 0) {
			FUN_100a66a0(p_roi);
		}

		p_roi->SetUnknown0xe0(-1);
		const CompoundObject* comp = p_roi->GetComp();

		if (comp != NULL) {
			for (CompoundObject::const_iterator it = comp->begin(); !(it == comp->end()); it++) {
				if ((ViewROI*) *it != NULL) {
					RemoveAll((ViewROI*) *it);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100a66a0
void ViewManager::FUN_100a66a0(ViewROI* p_roi)
{
	const ViewLOD* lod = (const ViewLOD*) p_roi->GetLOD(p_roi->GetUnknown0xe0());

	if (lod != NULL) {
		const Tgl::MeshBuilder* meshBuilder = NULL;
		Tgl::Group* roiGeometry = p_roi->GetGeometry();

		meshBuilder = lod->GetMeshBuilder();

		if (meshBuilder != NULL) {
			roiGeometry->Remove(meshBuilder);
		}

		scene->Remove(roiGeometry);
	}

	p_roi->SetUnknown0xe0(-1);
}

// STUB: LEGO1 0x100a6930
void ViewManager::Update(float p_previousRenderTime, float p_und2)
{
	// TODO
}

// FUNCTION: LEGO1 0x100a6b90
void ViewManager::FUN_100a6b90()
{
	flags &= ~c_bit2;

	// TODO: Should be signed, but worsens match
	unsigned int i, j, k;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 3; j++) {
			unk0xf0[i][j] = pov[3][j];

			for (k = 0; k < 3; k++) {
				unk0xf0[i][j] += pov[k][j] * unk0x90[i][k];
			}
		}
	}

	for (i = 0; i < 6; i++) {
		Vector3 a(unk0xf0[g_unk0x100dbcd8[i * 3]]);
		Vector3 b(unk0xf0[g_unk0x100dbcd8[i * 3 + 1]]);
		Vector3 c(unk0xf0[g_unk0x100dbcd8[i * 3 + 2]]);
		Mx3DPointFloat x;
		Mx3DPointFloat y;
		Vector3 u(unk0x150[i]);

		x = c;
		((Vector3&) x).Sub(&b); // TODO: Fix call

		y = a;
		((Vector3&) y).Sub(&b); // TODO: Fix call

		u.EqualsCross(&x, &y);
		u.Unitize();

		unk0x150[i][3] = -u.Dot(&u, &a);
	}

	flags |= c_bit4;
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

// STUB: LEGO1 0x100a6e00
ViewROI* ViewManager::Pick(Tgl::View* p_view, unsigned long x, unsigned long y)
{
	// TODO
	return NULL;
}

inline undefined4 GetD3DRM(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer)
{
	d3drm = ((TglImpl::RendererImpl*) pRenderer)->ImplementationData();
	return 0;
}

inline undefined4 GetFrame(IDirect3DRMFrame2*& frame, Tgl::Group* scene)
{
	frame = ((TglImpl::GroupImpl*) scene)->ImplementationData();
	return 0;
}
