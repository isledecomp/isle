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
ViewportAppData::ViewportAppData(IDirect3DRM2* pRenderer)
{
	pRenderer->CreateFrame(NULL, &m_pLightFrame);
	m_pCamera = NULL;
	m_pLastRenderedFrame = NULL;
	m_backgroundColorRed = 0.0f;
	m_backgroundColorGreen = 0.0f;
	m_backgroundColorBlue = 0.0f;
}

// FUNCTION: LEGO1 0x100a10e0
ViewportAppData::~ViewportAppData()
{
	IDirect3DRMFrameArray* pChildFrames;
	IDirect3DRMFrame* pChildFrame = NULL;
	m_pLightFrame->GetChildren(&pChildFrames);
	for (int i = 0; i < (int) pChildFrames->GetSize(); i++) {
		pChildFrames->GetElement(i, &pChildFrame);
		m_pLightFrame->DeleteChild(pChildFrame);
		pChildFrame->Release(); // GetElement() does AddRef()
	}
	pChildFrames->Release();
	m_pLightFrame->Release();
}

// Forward declare to satisfy order check
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg);

// FUNCTION: LEGO1 0x100a1160
Result ViewImpl::ViewportCreateAppData(IDirect3DRM2* pDevice, IDirect3DRMViewport* pView, IDirect3DRMFrame2* pCamera)
{
	ViewportAppData* data = new ViewportAppData(pDevice);
	data->m_pCamera = pCamera;
	Result result = ResultVal(pView->SetAppData(reinterpret_cast<LPD3DRM_APPDATA>(data)));
	if (Succeeded(result)) {
		result = ResultVal(pView->AddDestroyCallback(ViewportDestroyCallback, data));
	}
	if (!Succeeded(result)) {
		delete data;
		pView->SetAppData(0);
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
void ViewportDestroyCallback(IDirect3DRMObject* pObject, void* pArg)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(pArg);

	ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);

	delete pViewportAppData;
}

// FUNCTION: LEGO1 0x100a1290
Result ViewportPickImpl(
	IDirect3DRMViewport* pViewport,
	int x,
	int y,
	const Group** ppGroupsToPickFrom,
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

// FUNCTION: LEGO1 0x100a2e70
Result ViewImpl::SetProjection(ProjectionType type)
{
	return ResultVal(m_data->SetProjection(Translate(type)));
}

// FUNCTION: LEGO1 0x100a2eb0
Result ViewImpl::SetFrustrum(float frontClippingDistance, float backClippingDistance, float degrees)
{
	float field = frontClippingDistance * tan(DegreesToRadians(degrees / 2));
	Result result;
	result = ResultVal(m_data->SetFront(frontClippingDistance));
	if (Succeeded(result)) {
		result = ResultVal(m_data->SetBack(backClippingDistance));
	}
	if (Succeeded(result)) {
		result = ResultVal(m_data->SetField(field));
	}

	return result;
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
	}

	assert(Succeeded(result));

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

// FUNCTION: LEGO1 0x100a3080
Result ViewImpl::ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height)
{
	return ResultVal(m_data->ForceUpdate(x, y, x + width - 1, y + height - 1));
}

// FUNCTION: LEGO1 0x100a30c0
Result ViewImpl::Pick(
	unsigned long x,
	unsigned long y,
	const Group** ppGroupsToPickFrom,
	int groupsToPickFromCount,
	const Group**& rppPickedGroups,
	int& rPickedGroupCount
)
{
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

// FUNCTION: LEGO1 0x100a30f0
Result ViewImpl::TransformWorldToScreen(const float world[3], float screen[4])
{
	D3DRMVECTOR4D d3dRMScreen;
	D3DVECTOR d3dRMWorld;
	d3dRMWorld.x = world[0];
	d3dRMWorld.y = world[1];
	d3dRMWorld.z = world[2];
	Result result;

	result = ResultVal(m_data->Transform(&d3dRMScreen, &d3dRMWorld));

	if (Succeeded(result)) {
		screen[0] = d3dRMScreen.x;
		screen[1] = d3dRMScreen.y;
		screen[2] = d3dRMScreen.z;
		screen[3] = d3dRMScreen.w;
	}

	return result;
}

// FUNCTION: LEGO1 0x100a3160
Result ViewImpl::TransformScreenToWorld(const float screen[4], float world[3])
{
	// 100% match minus instruction reordering.
	D3DVECTOR d3dRMWorld;
	D3DRMVECTOR4D d3dScreen;
	d3dScreen.x = screen[0];
	d3dScreen.y = screen[1];
	d3dScreen.z = screen[2];
	d3dScreen.w = screen[3];
	Result result;

	result = ResultVal(m_data->InverseTransform(&d3dRMWorld, &d3dScreen));

	if (Succeeded(result)) {
		world[0] = d3dRMWorld.x;
		world[1] = d3dRMWorld.y;
		world[2] = d3dRMWorld.z;
	}

	return result;
}
