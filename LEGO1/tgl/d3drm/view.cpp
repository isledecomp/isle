#include "impl.h"

using namespace TglImpl;

struct ViewportAppData {
	ViewportAppData(IDirect3DRM* p_renderer);
	~ViewportAppData();

	IDirect3DRMFrame* m_pLightFrame;
	IDirect3DRMFrame* m_pCamera;
	IDirect3DRMFrame* m_pLastRenderedFrame;
	float m_backgroundColorRed;
	float m_backgroundColorGreen;
	float m_backgroundColorBlue;
};

// OFFSET: LEGO1 0x100a10b0
ViewportAppData::ViewportAppData(IDirect3DRM* p_renderer)
{
	p_renderer->CreateFrame(NULL, &m_pLightFrame);
	m_pCamera = NULL;
	m_pLastRenderedFrame = NULL;
	m_backgroundColorRed = 0.0f;
	m_backgroundColorGreen = 0.0f;
	m_backgroundColorBlue = 0.0f;
}

// OFFSET: LEGO1 0x100a10e0
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

DECOMP_SIZE_ASSERT(ViewportAppData, 0x18);

inline ViewportAppData* ViewportGetData(IDirect3DRMViewport* p_viewport)
{
	return reinterpret_cast<ViewportAppData*>(p_viewport->GetAppData());
}

inline IDirect3DRMFrame* ViewportGetLightFrame(IDirect3DRMViewport* p_viewport)
{
	return ViewportGetData(p_viewport)->m_pLightFrame;
}

// Inlined only
ViewImpl::~ViewImpl()
{
	if (m_data) {
		m_data->Release();
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a2d80
void* ViewImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// OFFSET: LEGO1 0x100a2d90
Result ViewImpl::Add(const Light* p_light)
{
	const LightImpl* light = static_cast<const LightImpl*>(p_light);
	IDirect3DRMFrame* frame = light->ImplementationData();
	return ResultVal(ViewportGetLightFrame(m_data)->AddChild(frame));
}

// OFFSET: LEGO1 0x100a2dc0
Result ViewImpl::Remove(const Light* p_light)
{
	const LightImpl* light = static_cast<const LightImpl*>(p_light);
	IDirect3DRMFrame* frame = light->ImplementationData();
	return ResultVal(ViewportGetLightFrame(m_data)->DeleteChild(frame));
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

// OFFSET: LEGO1 0x100a2df0
Result ViewImpl::SetCamera(const Camera* p_camera)
{
	const CameraImpl* camera = static_cast<const CameraImpl*>(p_camera);
	IDirect3DRMFrame* frame = camera->ImplementationData();

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

// OFFSET: LEGO1 0x100a2e70
Result ViewImpl::SetProjection(ProjectionType p_type)
{
	return ResultVal(m_data->SetProjection(Translate(p_type)));
}

// OFFSET: LEGO1 0x100a2eb0
Result ViewImpl::SetFrustrum(float p_frontClippingDistance, float p_backClippingDistance, float p_degrees)
{
	float field = p_frontClippingDistance * tan(DegreesToRadians(p_degrees / 2));
	Result result;
	result = ResultVal(m_data->SetFront(p_frontClippingDistance));
	if (Succeeded(result)) {
		result = ResultVal(m_data->SetBack(p_backClippingDistance));
	}
	if (Succeeded(result)) {
		result = ResultVal(m_data->SetField(field));
	}

	return result;
}

// OFFSET: LEGO1 0x100a2f30
Result ViewImpl::SetBackgroundColor(float p_r, float p_g, float p_b)
{
	Result ret = Success;
	// Note, this method in the shipped game is very diverged from
	// the Tgl leak code.
	ViewportAppData* data = ViewportGetData(m_data);
	data->m_backgroundColorRed = p_r;
	data->m_backgroundColorGreen = p_g;
	data->m_backgroundColorBlue = p_b;
	if (data->m_pLastRenderedFrame) {
		ret = ResultVal(data->m_pLastRenderedFrame->SetSceneBackgroundRGB(p_r, p_g, p_b));
	}
	return ret;
}

// OFFSET: LEGO1 0x100a2f80
Result ViewImpl::GetBackgroundColor(float* p_r, float* p_g, float* p_b)
{
	ViewportAppData* data = ViewportGetData(m_data);
	*p_r = data->m_backgroundColorRed;
	*p_g = data->m_backgroundColorGreen;
	*p_b = data->m_backgroundColorBlue;
	return Success;
}

// OFFSET: LEGO1 0x100a2fb0
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

// OFFSET: LEGO1 0x100a2fd0
Result ViewImpl::Render(const Light* p_camera)
{
	ViewportAppData* appdata = ViewportGetData(m_data);

	IDirect3DRMFrame* light = static_cast<const LightImpl*>(p_camera)->ImplementationData();

	IDirect3DRMFrame* lastRendered = appdata->m_pLastRenderedFrame;
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

// OFFSET: LEGO1 0x100a3080
Result ViewImpl::ForceUpdate(unsigned long x, unsigned long y, unsigned long width, unsigned long height)
{
	return ResultVal(m_data->ForceUpdate(x, y, x + width - 1, y + height - 1));
}

// OFFSET: LEGO1 0x100a30f0
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

// OFFSET: LEGO1 0x100a3160
Result ViewImpl::TransformScreenToWorld(const float p_screen[4], float p_world[3])
{
	// 100% match minus instruction reordering.
	D3DVECTOR d3dRMWorld;
	D3DRMVECTOR4D d3dScreen;
	d3dScreen.x = p_screen[0];
	d3dScreen.y = p_screen[1];
	d3dScreen.z = p_screen[2];
	d3dScreen.w = p_screen[3];
	Result result;

	result = ResultVal(m_data->InverseTransform(&d3dRMWorld, &d3dScreen));

	if (Succeeded(result)) {
		p_world[0] = d3dRMWorld.x;
		p_world[1] = d3dRMWorld.y;
		p_world[2] = d3dRMWorld.z;
	}

	return result;
}

// OFFSET: LEGO1 0x100a1290
Result ViewportPickImpl(
	IDirect3DRMViewport* p_viewport,
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

// OFFSET: LEGO1 0x100a30c0
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

// OFFSET: LEGO1 0x100a1240
void ViewportDestroyCallback(IDirect3DRMObject* p_object, void* p_arg)
{
	ViewportAppData* pViewportAppData = reinterpret_cast<ViewportAppData*>(p_arg);

	ViewRestoreFrameAfterRender(
		pViewportAppData->m_pLastRenderedFrame,
		pViewportAppData->m_pCamera,
		pViewportAppData->m_pLightFrame
	);

	delete pViewportAppData;
}

// OFFSET: LEGO1 0x100a1160
Result ViewImpl::ViewportCreateAppData(IDirect3DRM* p_device, IDirect3DRMViewport* p_view, IDirect3DRMFrame* p_camera)
{
	ViewportAppData* data = new ViewportAppData(p_device);
	data->m_pCamera = p_camera;
	Result result = ResultVal(p_view->SetAppData(reinterpret_cast<unsigned long>(data)));
	if (Succeeded(result)) {
		result = ResultVal(p_view->AddDestroyCallback(ViewportDestroyCallback, data));
	}
	if (!Succeeded(result)) {
		delete data;
		p_view->SetAppData(0);
	}
	return result;
}
