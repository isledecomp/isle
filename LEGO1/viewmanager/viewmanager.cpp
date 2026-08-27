#include "viewmanager.h"

#include "realtime/matrix4d.inl.h"
#include "realtime/vector3dtail.inl.h"

#include "mxdirectx/mxstopwatch.h"
#include "tgl/d3drm/tglimpl.h"
#include "viewlod.h"
#include "viewlod.inl.h"

#include <vec.h>

using namespace Tgl;
DECOMP_SIZE_ASSERT(ViewManager, 0x1bc)

// GLOBAL: LEGO1 0x100dbc78
// GLOBAL: BETA10 0x101c3398
const int g_boundingBoxCornerMap[8][3] =
	{{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {1, 0, 0}, {0, 1, 1}, {1, 0, 1}, {1, 1, 0}, {1, 1, 1}};

// GLOBAL: LEGO1 0x100dbcd8
const int g_planePointIndexMap[18] = {0, 1, 5, 6, 2, 3, 3, 0, 4, 1, 2, 6, 0, 3, 2, 4, 5, 6};

// GLOBAL: LEGO1 0x10101050
// GLOBAL: BETA10 0x10205914
float g_LODScaleFactor = 4.0F;

// GLOBAL: LEGO1 0x10101054
// GLOBAL: BETA10 0x10205918
float g_minLODThreshold = 1.0000005F / 1024;

// GLOBAL: LEGO1 0x10101058
// GLOBAL: BETA10 0x1020591c
int g_maxLODLevels = 6;

// GLOBAL: LEGO1 0x1010105c
float g_viewDistance = 0.000125F;

// GLOBAL: LEGO1 0x10101060
float g_elapsedSeconds = 0;

// FUNCTION: BETA10 0x10171f30
inline undefined4 GetD3DRM_viewmanager(IDirect3DRM2*& d3drm, Tgl::Renderer* p_tglRenderer)
{
	assert(p_tglRenderer);
	TglImpl::RendererImpl* renderer = (TglImpl::RendererImpl*) p_tglRenderer;
	// Note: Diff in BETA10 (thunked in recompile but not in orig)
	d3drm = renderer->ImplementationData();
	return 0;
}

// FUNCTION: BETA10 0x10171f82
inline undefined4 GetFrame(IDirect3DRMFrame2** p_f, Tgl::Group* p_group)
{
	assert(p_f && p_group);
	TglImpl::GroupImpl* cast = (TglImpl::GroupImpl*) p_group;
	assert(cast);
	*p_f = cast->ImplementationData();
	assert(p_f);
	return 0;
}

inline void SetAppData(ViewROI* p_roi, LPD3DRM_APPDATA data)
{
	IDirect3DRMFrame2* frame = NULL;

	if (GetFrame(&frame, p_roi->GetGeometry()) == 0) {
		frame->SetAppData(data);
	}
}

// STUB: BETA10 0x1017202e
int userVisualCallback(
	LPDIRECT3DRMUSERVISUAL obj,
	LPVOID arg,
	D3DRMUSERVISUALREASON reason,
	LPDIRECT3DRMDEVICE dev,
	LPDIRECT3DRMVIEWPORT view
)
{
	// This function calls into LegoBSP.cpp, which has likely been removed in LEGO1
	return 0;
}

// FUNCTION: BETA10 0x10172074
void addDestroyCallback(LPDIRECT3DRMOBJECT obj, LPVOID arg)
{
	// intentionally empty
}

// FUNCTION: LEGO1 0x100a5eb0
// FUNCTION: BETA10 0x10171cb3
ViewManager::ViewManager(Tgl::Renderer* pRenderer, Tgl::Group* scene, const OrientableROI* point_of_view)
	: scene(scene), flags(c_bit1 | c_bit2 | c_bit3 | c_bit4)
{
	SetPOVSource(point_of_view);
	prev_render_time = 0.09;
	GetD3DRM_viewmanager(d3drm, pRenderer);
	GetFrame(&frame, scene);

#ifdef BETA10
	LPDIRECT3DRMUSERVISUAL userVisual;
	if (d3drm->CreateUserVisual(userVisualCallback, this, &userVisual)) {
		assert(0);
	}
	if (userVisual->AddDestroyCallback(addDestroyCallback, this)) {
		assert(0);
	}
	if (frame->AddVisual(userVisual)) {
		assert(0);
	}
	userVisual->Release();
#endif

	width = 0.0;
	height = 0.0;
	view_angle = 0.0;
	pov.SetIdentity();
	front = 0.0;
	back = 0.0;

	memset(transformed_points, 0, sizeof(transformed_points));
	seconds_allowed = 1.0;
}

// FUNCTION: LEGO1 0x100a60c0
ViewManager::~ViewManager()
{
	SetPOVSource(NULL);
}

// FUNCTION: LEGO1 0x100a6150
// FUNCTION: BETA10 0x10172164
unsigned int ViewManager::IsBoundingBoxInFrustum(const BoundingBox& p_bounding_box)
{
	const Vector3* box[] = {&p_bounding_box.Min(), &p_bounding_box.Max()};

	float box_corners[8][3];
	int i, j, k;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 3; j++) {
			box_corners[i][j] = box[g_boundingBoxCornerMap[i][j]]->operator[](j);
		}
	}

	for (i = 0; i < 6; i++) {
		for (k = 0; k < 8; k++) {
			if (frustum_planes[i][0] * box_corners[k][0] + frustum_planes[i][2] * box_corners[k][2] +
					frustum_planes[i][1] * box_corners[k][1] + frustum_planes[i][3] >=
				0.0f) {
				break;
			}
		}

		if (k == 8) {
			return FALSE;
		}
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x100a6200
int ViewManager::FlushBuffers()
{
	LPDIRECT3DRMDEVICEARRAY deviceArray = NULL;

	if (d3drm != NULL && d3drm->GetDevices(&deviceArray) == D3DRM_OK) {
		if (deviceArray->GetSize() != 0) {
			LPDIRECT3DRMDEVICE device = NULL;

			if (deviceArray->GetElement(0, &device) == D3DRM_OK && device != NULL) {
				LPDIRECT3DRMDEVICE2 device2 = NULL;

				if (device->QueryInterface(IID_IDirect3DRMDevice2, (LPVOID*) &device2) == D3DRM_OK && device2 != NULL) {
					LPDIRECT3DRMVIEWPORTARRAY viewportArray = NULL;

					if (device->GetViewports(&viewportArray) == D3DRM_OK && viewportArray != NULL) {
						if (viewportArray->GetSize() != 0) {
							LPDIRECT3DRMVIEWPORT viewport = NULL;

							if (viewportArray->GetElement(0, &viewport) == D3DRM_OK && viewport != NULL) {
								LPDIRECT3DRMVISUALARRAY visuals = NULL;

								if (frame->GetVisuals(&visuals) == D3DRM_OK && visuals != NULL) {
									int i;
									int numVisuals = visuals->GetSize();

									for (i = 0; i < numVisuals; i++) {
										LPDIRECT3DRMVISUAL visual = NULL;

										if (visuals->GetElement(i, &visual) == D3DRM_OK && visual != NULL) {
											frame->DeleteVisual(visual);
										}
									}

									for (i = 0; i < 10; i++) {
										viewport->Render(frame);
										device->Update();
									}

									for (i = 0; i < numVisuals; i++) {
										LPDIRECT3DRMVISUAL visual = NULL;

										if (visuals->GetElement(i, &visual) == D3DRM_OK && visual != NULL) {
											frame->AddVisual(visual);
											visual->Release();
										}
									}

									visuals->Release();
								}

								viewport->Release();
							}
						}

						viewportArray->Release();
					}

					device2->Release();
				}

				device->Release();
			}
		}
	}

	return 0;
}

// The texture-refresh walk that vtable+0x04 held until late in development:
// Beta 9.0 (1997-07-25) still has it at 0x100a1880 and has no device/viewport
// FlushBuffers at all. By the August build the virtual had been rewritten into
// the form above and this recursion lost its only caller, so /OPT:REF discarded
// the code -- but the link had already resolved IID_IDirect3DRMFrame2 and
// pulled dxguid.lib(guid72.obj), whose 16 `.rdata` bytes are a whole-object,
// non-COMDAT contribution and so survive. That is why retail carries a twelfth
// SDK GUID at 0x100dd210 with zero references to it, and why a build without
// this function is 16 `.rdata` bytes short.
int FlushFrameBuffers(IDirect3DRMFrame2* p_frame)
{
	LPDIRECT3DRMVISUALARRAY visuals = NULL;

	if (p_frame->GetVisuals(&visuals) == D3DRM_OK && visuals != NULL) {
		int numVisuals = visuals->GetSize();

		for (int i = 0; i < numVisuals; i++) {
			LPDIRECT3DRMVISUAL visual = NULL;

			if (visuals->GetElement(i, &visual) == D3DRM_OK && visual != NULL) {
				LPDIRECT3DRMMESH mesh = NULL;

				if (visual->QueryInterface(IID_IDirect3DRMMesh, (LPVOID*) &mesh) == D3DRM_OK && mesh != NULL) {
					unsigned int numGroups = mesh->GetGroupCount();

					for (unsigned int j = 0; j < numGroups; j++) {
						LPDIRECT3DRMTEXTURE texture = NULL;

						if (mesh->GetGroupTexture(j, &texture) == D3DRM_OK && texture != NULL) {
							LPDIRECT3DRMTEXTURE2 texture2 = NULL;

							if (texture->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) &texture2) == D3DRM_OK &&
								texture2 != NULL) {
								mesh->SetGroupTexture(j, NULL);
								texture2->Changed(TRUE, TRUE);
								mesh->SetGroupTexture(j, texture);
								texture2->Release();
							}

							texture->Release();
						}
					}

					mesh->Release();
				}
				else {
					LPDIRECT3DRMFRAME2 childFrame = NULL;

					if (visual->QueryInterface(IID_IDirect3DRMFrame2, (LPVOID*) &childFrame) == D3DRM_OK &&
						childFrame != NULL) {
						FlushFrameBuffers(childFrame);
						childFrame->Release();
					}
				}

				visual->Release();
			}
		}

		visuals->Release();
	}

	return 0;
}

// FUNCTION: LEGO1 0x100a6410
// FUNCTION: BETA10 0x101722cd
void ViewManager::Remove(ViewROI* p_roi)
{
	for (CompoundObject::iterator it = rois.begin(); it != rois.end(); it++) {
		if (*it == p_roi) {
			rois.erase(it);

			if (p_roi->GetToken() >= 0) {
				RemoveROIDetailFromScene(p_roi);
			}

			const CompoundObject* comp = p_roi->GetComp();

			if (comp != NULL) {
				for (CompoundObject::const_iterator it = comp->begin(); !(it == comp->end()); it++) {
					if (((ViewROI*) *it)->GetToken() >= 0) {
						RemoveROIDetailFromScene((ViewROI*) *it);
					}
				}
			}

			return;
		}
	}
}

// FUNCTION: LEGO1 0x100a64d0
// FUNCTION: BETA10 0x101723f5
void ViewManager::RemoveAll(ViewROI* p_roi)
{
	if (p_roi == NULL) {
		for (CompoundObject::iterator it = rois.begin(); it != rois.end(); it++) {
			RemoveAll((ViewROI*) *it);
		}

		rois.erase(rois.begin(), rois.end());
	}
	else {
		if (p_roi->GetToken() >= 0) {
			RemoveROIDetailFromScene(p_roi);
		}

		p_roi->SetToken(ViewROI::c_tokenUnset);
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

// FUNCTION: LEGO1 0x100a65b0
// FUNCTION: BETA10 0x1017254b
void ViewManager::UpdateROIDetailBasedOnLOD(ViewROI* p_roi, int p_lodLevel)
{
	if (p_roi->GetLODCount() <= p_lodLevel) {
		p_lodLevel = p_roi->GetLODCount() - 1;
	}

	int lodLevel = p_roi->GetToken();

	if (lodLevel == p_lodLevel) {
		return;
	}

	Tgl::Group* group = p_roi->GetGeometry();
	Tgl::MeshBuilder* meshBuilder;
	ViewLOD* new_lod;
	Tgl::Result result;

	if (lodLevel < 0) {
		new_lod = (ViewLOD*) p_roi->GetLOD(p_lodLevel);
		assert(new_lod);

		if (new_lod->GetFlags() & ViewLOD::c_hasMesh) {
			result = scene->Add(group);
			assert(Succeeded(result));
			SetAppData(p_roi, reinterpret_cast<LPD3DRM_APPDATA>(p_roi));
		}
	}
	else {
		new_lod = (ViewLOD*) p_roi->GetLOD(lodLevel);

		if (new_lod != NULL) {
			meshBuilder = new_lod->GetMeshBuilder();

			if (meshBuilder != NULL) {
				result = group->Remove(meshBuilder);
				assert(Succeeded(result));
			}
		}

		new_lod = (ViewLOD*) p_roi->GetLOD(p_lodLevel);
		assert(new_lod);
	}

	if (new_lod->GetFlags() & ViewLOD::c_hasMesh) {
		meshBuilder = new_lod->GetMeshBuilder();

		if (meshBuilder != NULL) {
			result = group->Add(meshBuilder);
			assert(Succeeded(result));
			SetAppData(p_roi, reinterpret_cast<LPD3DRM_APPDATA>(p_roi));
			p_roi->SetToken(p_lodLevel);
			return;
		}
	}

	p_roi->SetToken(ViewROI::c_tokenUnset);
}

// FUNCTION: LEGO1 0x100a66a0
// FUNCTION: BETA10 0x101727c7
void ViewManager::RemoveROIDetailFromScene(ViewROI* p_from)
{
	const ViewLOD* lod = (const ViewLOD*) p_from->GetLOD(p_from->GetToken());

	if (lod != NULL) {
		const Tgl::MeshBuilder* meshBuilder = NULL;
		Tgl::Group* roiGeometry = p_from->GetGeometry();
		Tgl::Result result;

		meshBuilder = lod->GetMeshBuilder();

		if (meshBuilder != NULL) {
			result = roiGeometry->Remove(meshBuilder);
			assert(Succeeded(result));
		}

		result = scene->Remove(roiGeometry);
		assert(Succeeded(result));
	}

	p_from->SetToken(ViewROI::c_tokenUnset);
}

// FUNCTION: LEGO1 0x100a66f0
// FUNCTION: BETA10 0x1017297f
void ViewManager::ManageVisibilityAndDetailRecursively(ViewROI* p_from, int p_lodLevel)
{
	float projectedSize;
	assert(p_from);

	if (!p_from->GetVisibility() && p_lodLevel != ViewROI::c_tokenInvisible) {
		ManageVisibilityAndDetailRecursively(p_from, ViewROI::c_tokenInvisible);
	}
	else {
		const CompoundObject* comp = p_from->GetComp();

		if (p_lodLevel == ViewROI::c_tokenUnset) {
			if (p_from->GetWorldBoundingSphere().Radius() > 0.001F) {
				projectedSize = ProjectedSize(p_from->GetWorldBoundingSphere());

				if (projectedSize < seconds_allowed * g_viewDistance) {
					if (p_from->GetToken() != ViewROI::c_tokenInvisible) {
						ManageVisibilityAndDetailRecursively(p_from, ViewROI::c_tokenInvisible);
					}

					return;
				}
				else {
					p_lodLevel =
						CalculateLODLevel(projectedSize, RealtimeView::GetUserMaxLodPower() * seconds_allowed, p_from);
				}
			}
		}

		if (p_lodLevel == ViewROI::c_tokenInvisible) {
			if (p_from->GetToken() >= 0) {
				RemoveROIDetailFromScene(p_from);
				p_from->SetToken(ViewROI::c_tokenInvisible);
			}

			if (comp != NULL) {
				for (CompoundObject::const_iterator it = comp->begin(); it != comp->end(); it++) {
					ManageVisibilityAndDetailRecursively((ViewROI*) *it, p_lodLevel);
				}
			}
		}
		else if (comp == NULL) {
			if (p_from->GetLODs() != NULL && p_from->GetLODCount() > 0) {
				UpdateROIDetailBasedOnLOD(p_from, p_lodLevel);
			}
		}
		else {
			p_from->SetToken(ViewROI::c_tokenUnset);

			for (CompoundObject::const_iterator it = comp->begin(); it != comp->end(); it++) {
				// LINE: BETA10 0x10172bbd
				ManageVisibilityAndDetailRecursively((ViewROI*) *it, p_lodLevel);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100a6930
void ViewManager::Update(float p_previousRenderTime, float)
{
	MxStopWatch stopWatch;
	stopWatch.Start();

	prev_render_time = p_previousRenderTime;
	flags |= c_bit1;

	if (flags & c_bit3) {
		CalculateFrustumTransformations();
	}
	else if (flags & c_bit2) {
		UpdateViewTransformations();
	}

	for (CompoundObject::iterator it = rois.begin(); !(it == rois.end()); it++) {
		ManageVisibilityAndDetailRecursively((ViewROI*) *it, ViewROI::c_tokenUnset);
	}

	stopWatch.Stop();
	g_elapsedSeconds = stopWatch.ElapsedSeconds();
}

inline int ViewManager::CalculateFrustumTransformations()
{
	flags &= ~c_bit3;

	if (height == 0.0F || front == 0.0F) {
		return -1;
	}
	else {
		float fVar7 = tan(view_angle / 2.0F);
		view_area_at_one = fVar7 * fVar7 * 4.0F;

		float fVar1 = front * fVar7;
		float fVar2 = (width / height) * fVar1;
		float uVar6 = front;
		float fVar3 = back + front;
		float fVar4 = fVar3 / front;
		float fVar5 = fVar4 * fVar1;
		fVar4 = fVar4 * fVar2;

		float* frustumVertices = (float*) this->frustum_vertices;

		// clang-format off
		*frustumVertices = fVar2; frustumVertices++;
		*frustumVertices = fVar1; frustumVertices++;
		*frustumVertices = uVar6; frustumVertices++;
		*frustumVertices = fVar2; frustumVertices++;
		*frustumVertices = -fVar1; frustumVertices++;
		*frustumVertices = uVar6; frustumVertices++;
		*frustumVertices = -fVar2; frustumVertices++;
		*frustumVertices = -fVar1; frustumVertices++;
		*frustumVertices = uVar6; frustumVertices++;
		*frustumVertices = -fVar2; frustumVertices++;
		*frustumVertices = fVar1; frustumVertices++;
		*frustumVertices = uVar6; frustumVertices++;
		*frustumVertices = fVar4; frustumVertices++;
		*frustumVertices = fVar5; frustumVertices++;
		*frustumVertices = fVar3; frustumVertices++;
		*frustumVertices = fVar4; frustumVertices++;
		*frustumVertices = -fVar5; frustumVertices++;
		*frustumVertices = fVar3; frustumVertices++;
		*frustumVertices = -fVar4; frustumVertices++;
		*frustumVertices = -fVar5; frustumVertices++;
		*frustumVertices = fVar3; frustumVertices++;
		*frustumVertices = -fVar4; frustumVertices++;
		*frustumVertices = fVar5; frustumVertices++;
		*frustumVertices = fVar3;
		// clang-format on

		UpdateViewTransformations();
		return 0;
	}
}

// FUNCTION: BETA10 0x10172be5
inline int ViewManager::CalculateLODLevel(float p_maximumScale, float p_initialScale, ViewROI* from)
{
	int lodLevel;

	assert(from);

	if (GetFirstLODIndex(from) != 0) {
		if (p_maximumScale < g_minLODThreshold) {
			return 0;
		}
		else {
			// LINE: BETA10 0x10172c4d
			lodLevel = 1;
		}
	}
	else {
		lodLevel = 0;
	}

	for (float i = p_initialScale; lodLevel < g_maxLODLevels; lodLevel++) {
		if (i >= p_maximumScale) {
			break;
		}

		i = g_LODScaleFactor * i;
	}

	return lodLevel;
}

// FUNCTION: BETA10 0x10172cb0
inline int ViewManager::GetFirstLODIndex(ViewROI* p_roi)
{
	const LODListBase* lods = p_roi->GetLODs();

	if (lods != NULL && lods->Size() > 0) {
		if (((ViewLOD*) p_roi->GetLOD(0))->IsExtraLOD()) {
			return 1;
		}
		else {
			return 0;
		}
	}

	const CompoundObject* comp = p_roi->GetComp();

	if (comp != NULL) {
		for (CompoundObject::const_iterator it = comp->begin(); it != comp->end(); it++) {
			const LODListBase* lods = ((ViewROI*) *it)->GetLODs();

			if (lods != NULL && lods->Size() > 0) {
				if (((ViewLOD*) ((ViewROI*) *it)->GetLOD(0))->IsExtraLOD()) {
					return 1;
				}
				else {
					return 0;
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x100a6b90
void ViewManager::UpdateViewTransformations()
{
	flags &= ~c_bit2;

	int i, j, k;

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 3; j++) {
			transformed_points[i][j] = pov[3][j];

			for (k = 0; k < 3; k++) {
				transformed_points[i][j] += pov[k][j] * frustum_vertices[i][k];
			}
		}
	}

	for (i = 0; i < 6; i++) {
		Vector3 a((const float*) transformed_points[g_planePointIndexMap[i * 3]]);
		Vector3 b((const float*) transformed_points[g_planePointIndexMap[i * 3 + 1]]);
		Vector3 c(transformed_points[g_planePointIndexMap[i * 3 + 2]]);
		Mx3DPointFloat x;
		Mx3DPointFloat y;
		float* plane = frustum_planes[i];
		Vector3 normal(plane);

		x = c;
		x -= b;

		y = a;
		y -= b;

		normal.EqualsCross(x, y);
		normal.Unitize();

		plane[3] = -normal.Dot(normal, a);
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
// FUNCTION: BETA10 0x10173977
void ViewManager::SetPOVSource(const OrientableROI* point_of_view)
{
	if (point_of_view != NULL) {
		pov = point_of_view->GetLocal2World();
		flags |= c_bit2;
	}
}

// FUNCTION: LEGO1 0x100a6dc0
// FUNCTION: BETA10 0x101739b8
float ViewManager::ProjectedSize(const BoundingSphere& p_bounding_sphere)
{
	// The algorithm projects the radius of bounding sphere onto the perpendicular
	// plane one unit in front of the camera. That value is simply the ratio of the
	// radius to the distance from the camera to the sphere center. The projected size
	// is then the ratio of the area of that projected circle to the view surface area
	// at Z == 1.0.
	//
	float sphere_projected_area = 3.14159265359 * p_bounding_sphere.Radius() * p_bounding_sphere.Radius();
	float square_dist_to_sphere = DISTSQRD3(p_bounding_sphere.Center(), pov[3]);
	return sphere_projected_area / view_area_at_one / square_dist_to_sphere;
}

// FUNCTION: LEGO1 0x100a6e00
ViewROI* ViewManager::Pick(Tgl::View* p_view, unsigned long x, unsigned long y)
{
	LPDIRECT3DRMPICKEDARRAY picked = NULL;
	ViewROI* result = NULL;
	TglImpl::ViewImpl* view = (TglImpl::ViewImpl*) p_view;
	IDirect3DRMViewport* d3drm = view->ImplementationData();

	if (d3drm->Pick(x, y, &picked) != D3DRM_OK) {
		return NULL;
	}

	if (picked != NULL) {
		if (picked->GetSize() != 0) {
			LPDIRECT3DRMVISUAL visual;
			LPDIRECT3DRMFRAMEARRAY frameArray;
			D3DRMPICKDESC desc;

			if (picked->GetPick(0, &visual, &frameArray, &desc) == D3DRM_OK) {
				if (frameArray != NULL) {
					int size = frameArray->GetSize();

					if (size > 1) {
						for (int i = 1; i < size; i++) {
							LPDIRECT3DRMFRAME frame = NULL;

							if (frameArray->GetElement(i, &frame) == D3DRM_OK) {
								result = (ViewROI*) frame->GetAppData();

								if (result != NULL) {
									frame->Release();
									break;
								}

								frame->Release();
							}
						}
					}

					visual->Release();
					frameArray->Release();
				}
			}
		}

		picked->Release();
	}

	return result;
}

// FUNCTION: LEGO1 0x100a5e40
// FUNCTION: BETA10 0x10171bdf
ViewLOD::~ViewLOD()
{
	if (m_meshBuilder) {
		delete m_meshBuilder;
	}
	// something else happens on BETA10 here
}
