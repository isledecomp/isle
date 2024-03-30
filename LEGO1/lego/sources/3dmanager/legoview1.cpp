// LegoView1.cpp : implementation file
//

#include "legoview1.h"

#include "decomp.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxgeometry/mxmatrix.h"
#include "realtime/realtime.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoView, 0x78);
DECOMP_SIZE_ASSERT(LegoView1, 0x88);

// GLOBAL: LEGO1 0x101013e4
float g_sunLightRGB = 1.0;

// GLOBAL: LEGO1 0x101013e8
float g_directionalLightRGB = 1.0;

// GLOBAL: LEGO1 0x101013ec
float g_ambientLightRGB = 0.3;

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
	if (rCreateStruct.m_isWideViewAngle) {
		viewAngle = 90;
	}

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

// FUNCTION: LEGO1 0x100ab860
BOOL LegoView1::Create(const TglSurface::CreateStruct& rCreateStruct, Tgl::Renderer* pRenderer)
{
	if (!LegoView::Create(rCreateStruct, pRenderer)) {
		return FALSE;
	}

	// lights
	m_pSunLight = pRenderer->CreateLight(Tgl::Point, g_sunLightRGB, g_sunLightRGB, g_sunLightRGB);
	m_pDirectionalLight =
		pRenderer->CreateLight(Tgl::Directional, g_directionalLightRGB, g_directionalLightRGB, g_directionalLightRGB);
	m_pAmbientLight = pRenderer->CreateLight(Tgl::Ambient, g_ambientLightRGB, g_ambientLightRGB, g_ambientLightRGB);

	Mx3DPointFloat direction(0.0, 0.0, 0.0);
	Mx3DPointFloat position(0.0, -1.0, 0.0);
	Mx3DPointFloat up(1.0, 0.0, 0.0);

	Tgl::FloatMatrix4 matrix;
	Matrix4 in(matrix);
	MxMatrix transform;

	CalcLocalTransform(position, direction, up, transform);
	SETMAT4(in, transform);
	m_pDirectionalLight->SetTransformation(matrix);

	direction[0] = 0, direction[1] = 150, direction[2] = -150;
	CalcLocalTransform(position, direction, up, transform);
	SETMAT4(in, transform);
	m_pSunLight->SetTransformation(matrix);

	assert(GetView());

	return AddLightsToViewport();
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

// FUNCTION: LEGO1 0x100abb60
void LegoView1::SetLightTransform(BOOL bDirectionalLight, Tgl::FloatMatrix4& rMatrix)
{
	Tgl::Light* pLight;

	if (bDirectionalLight == FALSE) {
		pLight = m_pSunLight;
	}
	else {
		pLight = m_pDirectionalLight;
	}

	SetLightTransform(pLight, rMatrix);
}

// FUNCTION: LEGO1 0x100abb80
void LegoView1::SetLightTransform(Tgl::Light* pLight, Tgl::FloatMatrix4& rMatrix)
{
	pLight->SetTransformation(rMatrix);
}

// FUNCTION: LEGO1 0x100abba0
void LegoView1::SetLightColor(BOOL bDirectionalLight, float red, float green, float blue)
{
	Tgl::Light* pLight;

	if (bDirectionalLight == FALSE) {
		pLight = m_pSunLight;
	}
	else {
		pLight = m_pDirectionalLight;
	}

	SetLightColor(pLight, red, green, blue);
}

// FUNCTION: LEGO1 0x100abbd0
void LegoView1::SetLightColor(Tgl::Light* pLight, float red, float green, float blue)
{
	pLight->SetColor(red, green, blue);
}
