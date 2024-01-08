// LegoView1.cpp : implementation file
//

#include "legoview1.h"

#include "decomp.h"
#include "realtime/realtime.h"

#include <vec.h> // SETMAT4

DECOMP_SIZE_ASSERT(LegoView, 0x78);
DECOMP_SIZE_ASSERT(LegoView1, 0x88);

/////////////////////////////////////////////////////////////////////////////
// LegoView

// FUNCTION: LEGO1 0x100ab510
LegoView::LegoView()
{
	m_pScene = 0;
	m_pCamera = 0;
}

// FUNCTION: LEGO1 0x100ab5a0
LegoView::~LegoView()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ab600
BOOL LegoView::Create(const TglSurface::CreateStruct& rCreateStruct, Tgl::Renderer* pRenderer)
{
	float viewAngle = 45;
	if (rCreateStruct.m_isWideViewAngle)
		viewAngle = 90;

	float frontClippingDistance = 0.1;
	float backClippingDistance = 500;

	assert(!m_pScene);
	assert(!m_pCamera);
	assert(pRenderer);

	m_pScene = pRenderer->CreateGroup();
	assert(m_pScene);
	// TglSurface::Create() calls CreateView(), and we need the camera in
	// CreateView(), so create camera before calling TglSurface::Create()
	m_pCamera = pRenderer->CreateCamera();
	assert(m_pCamera);

	if (!TglSurface::Create(rCreateStruct, pRenderer, m_pScene)) {
		delete m_pScene;
		m_pScene = 0;

		delete m_pCamera;
		m_pCamera = 0;

		return FALSE;
	}

	assert(GetView());
	GetView()->SetFrustrum(frontClippingDistance, backClippingDistance, viewAngle);
	GetView()->SetBackgroundColor(.223, .639, .851);

	return TRUE;
}

// FUNCTION: LEGO1 0x100ab6c0
Tgl::View* LegoView::CreateView(Tgl::Renderer* pRenderer, Tgl::Device* pDevice)
{
	assert(pRenderer);
	assert(pDevice);

	return pRenderer->CreateView(pDevice, m_pCamera, 0, 0, GetWidth(), GetHeight());
}

// FUNCTION: LEGO1 0x100ab6f0
void LegoView::Destroy()
{
	delete m_pScene;
	m_pScene = 0;

	delete m_pCamera;
	m_pCamera = 0;

	TglSurface::Destroy();
}

/////////////////////////////////////////////////////////////////////////////
// LegoView1

// FUNCTION: LEGO1 0x100ab730
LegoView1::LegoView1()
{
	m_pSunLight = 0;
	m_pDirectionalLight = 0;
	m_pAmbientLight = 0;
}

// FUNCTION: LEGO1 0x100ab7c0
LegoView1::~LegoView1()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ab820
BOOL LegoView1::AddLightsToViewport()
{
	GetView()->Add(m_pSunLight);
	GetView()->Add(m_pDirectionalLight);
	GetView()->Add(m_pAmbientLight);
	return TRUE;
}

// STUB: LEGO1 0x100ab860
BOOL LegoView1::Create(const TglSurface::CreateStruct& rCreateStruct, Tgl::Renderer* pRenderer)
{
	double position[3] = {0, 0, 0};
	double direction[3];
	double up[3] = {0, 1, 0};

	if (!LegoView::Create(rCreateStruct, pRenderer)) {
		return FALSE;
	}

	// lights
	m_pSunLight = pRenderer->CreateLight(Tgl::Directional, .9, .9, .9);
	m_pDirectionalLight = pRenderer->CreateLight(Tgl::Directional, .4, .4, .4);
	m_pAmbientLight = pRenderer->CreateLight(Tgl::Ambient, .3, .3, .3);

#if 0
    direction[0] = 1, direction[1] = -1, direction[2] = 2;
    m_pSunLight->SetOrientation(direction, up);
    direction[0] = -1, direction[1] = -2, direction[2] = -1;
    m_pDirectionalLight->SetOrientation(direction, up);
#else
	{
		// Change everything to float and proper Matrix types
		/*
		Tgl::FloatMatrix4 transformation;
		Matrix4Data transform;

		direction[0] = 1, direction[1] = -1, direction[2] = 2;
		CalcLocalTransform(position, direction, up, transform);
		SETMAT4(transformation, transform);
		m_pSunLight->SetTransformation(transformation);

		direction[0] = -1, direction[1] = -2, direction[2] = -1;
		CalcLocalTransform(position, direction, up, transform);
		SETMAT4(transformation, transform);
		m_pDirectionalLight->SetTransformation(transformation);
		*/
	}
#endif

	assert(GetView());
	AddLightsToViewport();

	return TRUE;
}

// FUNCTION: LEGO1 0x100abad0
void LegoView1::Destroy()
{
	if (m_pSunLight) {
		GetView()->Remove(m_pSunLight);
		delete m_pSunLight;
		m_pSunLight = 0;
	}

	if (m_pDirectionalLight) {
		GetView()->Remove(m_pDirectionalLight);
		delete m_pDirectionalLight;
		m_pDirectionalLight = 0;
	}

	if (m_pAmbientLight) {
		GetView()->Remove(m_pAmbientLight);
		delete m_pAmbientLight;
		m_pAmbientLight = 0;
	}

	LegoView::Destroy();
}
