#include "impl.h"

#include <assert.h>

using namespace TglImpl;

struct ViewportAppData {
	ViewportAppData(IDirect3DRM2* pRenderer);
	~ViewportAppData();

	IDirect3DRMFrame2* m_pLightFrame;
	IDirect3DRMFrame2* m_pCamera;
	IDirect3DRMFrame2* m_pLastRenderedFrame;
	float m_backgroundColorRed;
	float m_backgroundColorGreen;
	float m_backgroundColorBlue;
};

DECOMP_SIZE_ASSERT(ViewportAppData, 0x18);

// FUNCTION: LEGO1 0x100a10b0
// FUNCTION: BETA10 0x10168920
ViewportAppData::ViewportAppData(IDirect3DRM2* pRenderer)
{
	Result result = ResultVal(pRenderer->CreateFrame(NULL, &m_pLightFrame));
	assert(Succeeded(result));

	m_pCamera = NULL;
	m_pLastRenderedFrame = NULL;
	m_backgroundColorRed = 0.0f;
	m_backgroundColorGreen = 0.0f;
	m_backgroundColorBlue = 0.0f;
}

// FUNCTION: LEGO1 0x100a10e0
// FUNCTION: BETA10 0x101689bd
ViewportAppData::~ViewportAppData()
{
	int refCount;
	IDirect3DRMFrameArray* pChildFrames;
	IDirect3DRMFrame* pChildFrame = NULL;
	Result result = ResultVal(m_pLightFrame->GetChildren(&pChildFrames));
	assert(Succeeded(result));

	for (int i = 0; i < (int) pChildFrames->GetSize(); i++) {
		result = ResultVal(pChildFrames->GetElement(i, &pChildFrame));
		assert(Succeeded(result));

		result = ResultVal(m_pLightFrame->DeleteChild(pChildFrame));
		assert(Succeeded(result));

		refCount = pChildFrame->Release(); // GetElement() does AddRef()
		assert(refCount >= 1);
	}

	refCount = pChildFrames->Release();
	assert(refCount == 0);

	refCount = m_pLightFrame->Release();
	assert(refCount == 0);
}

// Forward declare to satisfy order check
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg);

// FUNCTION: LEGO1 0x100a1160
// FUNCTION: BETA10 0x10168ba5
Result ViewImpl::ViewportCreateAppData(
	IDirect3DRM2* pDevice,
	IDirect3DRMViewport* pViewport,
	IDirect3DRMFrame2* pCamera
)
{
	ViewportAppData* pViewportAppData = new ViewportAppData(pDevice);
	assert(pViewportAppData);

	pViewportAppData->m_pCamera = pCamera;
	assert(!pViewport->GetAppData());

	Result result = ResultVal(pViewport->SetAppData(reinterpret_cast<LPD3DRM_APPDATA>(pViewportAppData)));
	assert(Succeeded(result));
	assert(reinterpret_cast<ViewportAppData*>(pViewport->GetAppData()) == pViewportAppData);

	if (Succeeded(result)) {
		result = ResultVal(pViewport->AddDestroyCallback(ViewportDestroyCallback, pViewportAppData));
		assert(Succeeded(result));
	}

	if (!Succeeded(result)) {
		delete pViewportAppData;
		pViewport->SetAppData(0);
	}

	return result;
}

// FUNCTION: BETA10 0x1016bd80
inline Result ViewRestoreFrameAfterRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame
)
{
	Result result = Success;
	if (pFrame) {
		// remove camera and light frame from frame that was rendered
		// this doesn't destroy the camera as it is still the camera of the viewport...
		result = ResultVal(pFrame->DeleteChild(pCamera));
		assert(Succeeded(result));
		assert((pCamera->AddRef(), pCamera->Release()) > 0);

		result = ResultVal(pFrame->DeleteChild(pLightFrame));
		assert(Succeeded(result));

		// decrease frame's ref count (it was increased in ViewPrepareFrameForRender())
		pFrame->Release();
	}
	return result;
}

// FIXME: from LEGO1/tgl/d3drm/view.cpp

// FUNCTION: LEGO1 0x100a1240
// FUNCTION: BETA10 0x10168dc9
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pArg);
	assert(static_cast<ViewImpl::ViewDataType>(pObject));
	assert(pViewportAppData);

	Result result = ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);

	assert(Succeeded(result));

	delete pViewportAppData;
}

// FUNCTION: LEGO1 0x100a1290
// FUNCTION: BETA10 0x10168eab
Result ViewportPickImpl(
	IDirect3DRMViewport* pViewport,
	int x,
	int y,
	const GroupImpl** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	// Left unimplemented in shipped game.
	return Error;
}

inline ViewportAppData* ViewportGetData(IDirect3DRMViewport* pViewport)
{
	return reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
}

// FUNCTION: BETA10 0x10170ab0
inline IDirect3DRMFrame* ViewportGetLightFrame(IDirect3DRMViewport* pViewport)
{
	assert(pViewport->GetAppData());
	return reinterpret_cast<ViewportAppData*>(pViewport->GetAppData())->m_pLightFrame;
}

// FUNCTION: LEGO1 0x100a2d80
// FUNCTION: BETA10 0x1016e640
void* ViewImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x10170a40
inline Result ViewAddLight(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame* pLight)
{
	IDirect3DRMFrame* pLightFrame = ViewportGetLightFrame(pViewport);

	assert(pLightFrame);
	return ResultVal(pLightFrame->AddChild(const_cast<IDirect3DRMFrame*>(pLight)));
}

// FUNCTION: BETA10 0x101709a0
inline Result ViewImpl::Add(const LightImpl& rLight)
{
	assert(m_data);
	assert(rLight.ImplementationData());

	return ViewAddLight(m_data, rLight.ImplementationData());
}

// FUNCTION: LEGO1 0x100a2d90
// FUNCTION: BETA10 0x1016e690
Result ViewImpl::Add(const Light* pLight)
{
	assert(m_data);
	assert(pLight);

	return Add(*static_cast<const LightImpl*>(pLight));
}

// FUNCTION: BETA10 0x10170bb0
inline Result ViewRemoveLight(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame* pLight)
{
	IDirect3DRMFrame* pLightFrame = ViewportGetLightFrame(pViewport);

	assert(pLightFrame);
	return ResultVal(pLightFrame->DeleteChild(const_cast<IDirect3DRMFrame*>(pLight)));
}

// FUNCTION: BETA10 0x10170b10
inline Result ViewImpl::Remove(const LightImpl& rLight)
{
	assert(m_data);
	assert(rLight.ImplementationData());

	return ViewRemoveLight(m_data, rLight.ImplementationData());
}

// FUNCTION: LEGO1 0x100a2dc0
// FUNCTION: BETA10 0x1016e710
Result ViewImpl::Remove(const Light* pLight)
{
	assert(m_data);
	assert(pLight);

	return Remove(*static_cast<const LightImpl*>(pLight));
}

// FUNCTION: BETA10 0x10170cc0
inline Result ViewSetCamera(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame2* pCamera)
{
	ViewportAppData* pViewportAppData;
	Result result;

	pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	result = ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);
	assert(Succeeded(result));
	pViewportAppData->m_pCamera = const_cast<IDirect3DRMFrame2*>(pCamera);
	pViewportAppData->m_pLastRenderedFrame = 0;

	return ResultVal(pViewport->SetCamera(const_cast<IDirect3DRMFrame2*>(pCamera)));
}

// FUNCTION: BETA10 0x10170c20
inline Result ViewImpl::SetCamera(const CameraImpl& rCamera)
{
	assert(m_data);
	assert(rCamera.ImplementationData());

	return ViewSetCamera(m_data, rCamera.ImplementationData());
}

// FUNCTION: LEGO1 0x100a2df0
// FUNCTION: BETA10 0x1016e790
Result ViewImpl::SetCamera(const Camera* pCamera)
{
	assert(m_data);
	assert(pCamera);

	return SetCamera(*static_cast<const CameraImpl*>(pCamera));
}

// FUNCTION: BETA10 0x1016e870
inline Result ViewSetProjection(IDirect3DRMViewport* pViewport, ProjectionType type)
{
	D3DRMPROJECTIONTYPE projectionType = Translate(type);

	return ResultVal(pViewport->SetProjection(projectionType));
}

// FUNCTION: LEGO1 0x100a2e70
// FUNCTION: BETA10 0x1016e810
Result ViewImpl::SetProjection(ProjectionType type)
{
	assert(m_data);

	return ViewSetProjection(m_data, type);
}

// FUNCTION: BETA10 0x1016e920
inline Result ViewSetFrustrum(
	IDirect3DRMViewport* pViewport,
	float frontClippingDistance,
	float backClippingDistance,
	float degrees
)
{
	float field = frontClippingDistance * tan(DegreesToRadians(degrees / 2));
	Result result;
	result = ResultVal(pViewport->SetFront(frontClippingDistance));
	if (Succeeded(result)) {
		result = ResultVal(pViewport->SetBack(backClippingDistance));
	}
	if (Succeeded(result)) {
		result = ResultVal(pViewport->SetField(field));
	}

	return result;
}

// FUNCTION: LEGO1 0x100a2eb0
// FUNCTION: BETA10 0x1016e8b0
Result ViewImpl::SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees)
{
	assert(m_data);

	return ViewSetFrustrum(m_data, frontClippingDistance, backClippingDistance, degrees);
}

// FUNCTION: BETA10 0x1016ea70
inline Result ViewSetBackgroundColor(IDirect3DRMViewport* pViewport, float r, float g, float b)
{
	Result result = Success;

	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	pViewportAppData->m_backgroundColorRed = r;
	pViewportAppData->m_backgroundColorGreen = g;
	pViewportAppData->m_backgroundColorBlue = b;

	if (pViewportAppData->m_pLastRenderedFrame) {
		result = ResultVal(pViewportAppData->m_pLastRenderedFrame->SetSceneBackgroundRGB(r, g, b));
		assert(Succeeded(result));
	}

	return result;
}

// FUNCTION: LEGO1 0x100a2f30
// FUNCTION: BETA10 0x1016ea00
Result ViewImpl::SetBackgroundColor(float r, float g, float b)
{
	assert(m_data);

	return ViewSetBackgroundColor(m_data, r, g, b);
}

// FUNCTION: BETA10 0x1016ebd0
inline Result ViewGetBackgroundColor(IDirect3DRMViewport* pViewport, float* r, float* g, float* b)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	*r = pViewportAppData->m_backgroundColorRed;
	*g = pViewportAppData->m_backgroundColorGreen;
	*b = pViewportAppData->m_backgroundColorBlue;

	return Success;
}

// FUNCTION: LEGO1 0x100a2f80
// FUNCTION: BETA10 0x1016eb60
Result ViewImpl::GetBackgroundColor(float* r, float* g, float* b)
{
	assert(m_data);

	return ViewGetBackgroundColor(m_data, r, g, b);
}

// FUNCTION: BETA10 0x1016ecb0
inline Result ViewClear(IDirect3DRMViewport* pViewport)
{
	return ResultVal(pViewport->Clear());
}

// FUNCTION: LEGO1 0x100a2fb0
// FUNCTION: BETA10 0x1016ec50
Result ViewImpl::Clear()
{
	assert(m_data);

	return ViewClear(m_data);
}

// FUNCTION: BETA10 0x10170fb0
inline Result ViewPrepareFrameForRender(
	IDirect3DRMFrame* pFrame,
	IDirect3DRMFrame* pCamera,
	IDirect3DRMFrame* pLightFrame,
	float backgroundRed,
	float backgroundGreen,
	float backgroundBlue
)
{
	Result result = Success;

	if (pFrame) {
		// set background color
		result = ResultVal(pFrame->SetSceneBackgroundRGB(backgroundRed, backgroundGreen, backgroundBlue));
		assert(Succeeded(result));

		// add camera to frame to be rendered
		result = ResultVal(pFrame->AddChild(pCamera));
		assert(Succeeded(result));

		// add light frame to frame to be rendered
		result = ResultVal(pFrame->AddChild(pLightFrame));
		assert(Succeeded(result));

		// increase ref count of frame to ensure it does not get deleted underneath us
		pFrame->AddRef();
	}

	return result;
}

// FUNCTION: BETA10 0x10170e30
inline Result ViewRender(IDirect3DRMViewport* pViewport, const IDirect3DRMFrame2* pGroup)
{
	ViewportAppData* pViewportAppData;
	Result result;

	pViewportAppData = reinterpret_cast<ViewportAppData*>(pViewport->GetAppData());
	assert(pViewportAppData);

	if (pViewportAppData->m_pLastRenderedFrame != pGroup) {
		result = ViewRestoreFrameAfterRender(
			pViewportAppData->m_pLastRenderedFrame,
			pViewportAppData->m_pCamera,
			pViewportAppData->m_pLightFrame
		);

		assert(Succeeded(result));

		pViewportAppData->m_pLastRenderedFrame = const_cast<IDirect3DRMFrame2*>(pGroup);

		result = ViewPrepareFrameForRender(
			pViewportAppData->m_pLastRenderedFrame,
			pViewportAppData->m_pCamera,
			pViewportAppData->m_pLightFrame,
			pViewportAppData->m_backgroundColorRed,
			pViewportAppData->m_backgroundColorGreen,
			pViewportAppData->m_backgroundColorBlue
		);
	}

	assert(Succeeded(result));

	result = ResultVal(pViewport->Render(const_cast<IDirect3DRMFrame2*>(pGroup)));
	assert(Succeeded(result));

	return result;
}

// FUNCTION: BETA10 0x10170d90
inline Result ViewImpl::Render(const GroupImpl& rScene)
{
	assert(m_data);
	assert(rScene.ImplementationData());

	return ViewRender(m_data, rScene.ImplementationData());
}

// FUNCTION: LEGO1 0x100a2fd0
// FUNCTION: BETA10 0x1016ece0
Result ViewImpl::Render(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Render(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: BETA10 0x1016edd0
inline Result ViewForceUpdate(
	IDirect3DRMViewport* pViewport,
	unsigned long x,
	unsigned long y,
	unsigned long width,
	unsigned long height
)
{
	return ResultVal(pViewport->ForceUpdate(x, y, x + width - 1, y + height - 1));
}

// FUNCTION: LEGO1 0x100a3080
// FUNCTION: BETA10 0x1016ed60
Result ViewImpl::ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height)
{
	assert(m_data);

	return ViewForceUpdate(m_data, x, y, width, height);
}

// FUNCTION: BETA10 0x101710f0
inline Result ViewImpl::Pick(
	unsigned long x,
	unsigned long y,
	const GroupImpl** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	assert(m_data);

	return ViewportPickImpl(
		m_data,
		x,
		y,
		ppGroupsToPickFrom,
		groupsToPickFromCount,
		rppPickedGroups,
		rPickedGroupCount
	);
}

// FUNCTION: LEGO1 0x100a30c0
// FUNCTION: BETA10 0x1016ee10
Result ViewImpl::Pick(
	unsigned long x,
	unsigned long y,
	const Group** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
	assert(m_data);

	return Pick(
		x,
		y,
		reinterpret_cast<const GroupImpl**>(ppGroupsToPickFrom),
		groupsToPickFromCount,
		rppPickedGroups,
		rPickedGroupCount
	);
}

// FUNCTION: BETA10 0x1016eff0
inline Result ViewTransformWorldToScreen(IDirect3DRMViewport* pViewport, const float world[3], float screen[4])
{
	D3DRMVECTOR4D d3dRMScreen;
	D3DVECTOR d3dRMWorld;
	D3DVECTOR* pD3DRMWorld = Translate(world, d3dRMWorld);
	Result result;

	result = ResultVal(pViewport->Transform(&d3dRMScreen, pD3DRMWorld));

	if (Succeeded(result)) {
		screen[0] = d3dRMScreen.x;
		screen[1] = d3dRMScreen.y;
		screen[2] = d3dRMScreen.z;
		screen[3] = d3dRMScreen.w;
	}

	return result;
}

// FUNCTION: LEGO1 0x100a30f0
// FUNCTION: BETA10 0x1016ef90
Result ViewImpl::TransformWorldToScreen(const float world[3], float screen[4])
{
	assert(m_data);

	return ViewTransformWorldToScreen(m_data, world, screen);
}

// FUNCTION: BETA10 0x1016f0d0
inline Result ViewTransformScreenToWorld(IDirect3DRMViewport* pViewport, const float screen[4], float world[3])
{
	D3DVECTOR d3dRMWorld;
	D3DRMVECTOR4D d3dScreen;
	d3dScreen.x = screen[0];
	d3dScreen.y = screen[1];
	d3dScreen.z = screen[2];
	d3dScreen.w = screen[3];
	Result result;

	result = ResultVal(pViewport->InverseTransform(&d3dRMWorld, &d3dScreen));

	if (Succeeded(result)) {
		world[0] = d3dRMWorld.x;
		world[1] = d3dRMWorld.y;
		world[2] = d3dRMWorld.z;
	}

	return result;
}

// FUNCTION: LEGO1 0x100a3160
// FUNCTION: BETA10 0x1016f070
Result ViewImpl::TransformScreenToWorld(const float screen[4], float world[3])
{
	assert(m_data);

	return ViewTransformScreenToWorld(m_data, screen, world);
}
