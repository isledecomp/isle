#include "impl.h"

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
	Result result = ResultVal(pView->SetAppData(reinterpret_cast<unsigned long>(data)));
	if (Succeeded(result)) {
		result = ResultVal(pView->AddDestroyCallback(ViewportDestroyCallback, data));
	}
	if (!Succeeded(result)) {
		delete data;
		pView->SetAppData(0);
	}
	return result;
}

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
		result = ResultVal(pFrame->DeleteChild(pLightFrame));

		// decrease frame's ref count (it was increased in ViewPrepareFrameForRender())
		pFrame->Release();
	}
	return result;
}

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

inline IDirect3DRMFrame* ViewportGetLightFrame(IDirect3DRMViewport* pViewport)
{
	return ViewportGetData(pViewport)->m_pLightFrame;
}

// FUNCTION: LEGO1 0x100a2d80
void* ViewImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a2d90
Result ViewImpl::Add(const Light* pLight)
{
	const LightImpl* light = static_cast<const LightImpl*>(pLight);
	IDirect3DRMFrame* frame = light->ImplementationData();
	return ResultVal(ViewportGetLightFrame(m_data)->AddChild(frame));
}

// FUNCTION: LEGO1 0x100a2dc0
Result ViewImpl::Remove(const Light* pLight)
{
	const LightImpl* light = static_cast<const LightImpl*>(pLight);
	IDirect3DRMFrame* frame = light->ImplementationData();
	return ResultVal(ViewportGetLightFrame(m_data)->DeleteChild(frame));
}

// FUNCTION: LEGO1 0x100a2df0
Result ViewImpl::SetCamera(const Camera* pCamera)
{
	const CameraImpl* camera = static_cast<const CameraImpl*>(pCamera);
	IDirect3DRMFrame2* frame = camera->ImplementationData();

	ViewportAppData* pViewportAppData;
	Result result;

	pViewportAppData = reinterpret_cast<ViewportAppData*>(m_data->GetAppData());
	result = ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);
	pViewportAppData->m_pCamera = frame;
	pViewportAppData->m_pLastRenderedFrame = 0;

	return ResultVal(m_data->SetCamera(frame));
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

// FUNCTION: LEGO1 0x100a2f30
Result ViewImpl::SetBackgroundColor(float r, float g, float b)
{
	Result ret = Success;
	// Note, this method in the shipped game is very diverged from
	// the Tgl leak code.
	ViewportAppData* data = ViewportGetData(m_data);
	data->m_backgroundColorRed = r;
	data->m_backgroundColorGreen = g;
	data->m_backgroundColorBlue = b;
	if (data->m_pLastRenderedFrame) {
		ret = ResultVal(data->m_pLastRenderedFrame->SetSceneBackgroundRGB(r, g, b));
	}
	return ret;
}

// FUNCTION: LEGO1 0x100a2f80
Result ViewImpl::GetBackgroundColor(float* r, float* g, float* b)
{
	ViewportAppData* data = ViewportGetData(m_data);
	*r = data->m_backgroundColorRed;
	*g = data->m_backgroundColorGreen;
	*b = data->m_backgroundColorBlue;
	return Success;
}

// FUNCTION: LEGO1 0x100a2fb0
Result ViewImpl::Clear()
{
	return ResultVal(m_data->Clear());
}

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

		// add camera to frame to be rendered
		result = ResultVal(pFrame->AddChild(pCamera));

		// add light frame to frame to be rendered
		result = ResultVal(pFrame->AddChild(pLightFrame));

		// increase ref count of frame to ensure it does not get deleted underneath us
		pFrame->AddRef();
	}

	return result;
}

// FUNCTION: LEGO1 0x100a2fd0
Result ViewImpl::Render(const Light* pCamera)
{
	ViewportAppData* appdata = ViewportGetData(m_data);

	IDirect3DRMFrame2* light = static_cast<const LightImpl*>(pCamera)->ImplementationData();

	IDirect3DRMFrame2* lastRendered = appdata->m_pLastRenderedFrame;
	if (light != lastRendered) {
		if (lastRendered) {
			lastRendered->DeleteChild(appdata->m_pCamera);
			// Some other call goes here, not sure what.
			lastRendered->Release();
		}
		appdata->m_pLastRenderedFrame = light;
		if (light) {
			light->SetSceneBackgroundRGB(
				appdata->m_backgroundColorRed,
				appdata->m_backgroundColorGreen,
				appdata->m_backgroundColorBlue
			);
			light->AddChild(appdata->m_pCamera);
			// Some other call goes here, not sure what.
			light->AddRef();
		}
	}
	return ResultVal(m_data->Render(light));
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
