// Lego3DManager.cpp : implementation file
//
#include "lego3dmanager.h"

#include "decomp.h"
#include "viewmanager/viewlodlist.h"

DECOMP_SIZE_ASSERT(Lego3DManager, 0x10);

//////////////////////////////////////////////////////////////////////////////

// FUNCTION: LEGO1 0x100ab2d0
BOOL InitializeCreateStruct(
	TglSurface::CreateStruct& rTglSurfaceCreateStruct,
	const Lego3DManager::CreateStruct& rCreateStruct
)
{
	// initializes a TglSurface::CreateStruct from a Lego3DManager::CreateStruct
	rTglSurfaceCreateStruct.m_pDriverGUID = rCreateStruct.m_pDriverGUID;
	rTglSurfaceCreateStruct.m_hWnd = rCreateStruct.m_hWnd;
	rTglSurfaceCreateStruct.m_pDirectDraw = rCreateStruct.m_pDirectDraw;
	rTglSurfaceCreateStruct.m_pFrontBuffer = rCreateStruct.m_pFrontBuffer;
	rTglSurfaceCreateStruct.m_pBackBuffer = rCreateStruct.m_pBackBuffer;
	rTglSurfaceCreateStruct.m_pPalette = rCreateStruct.m_pPalette;
	rTglSurfaceCreateStruct.m_isFullScreen = rCreateStruct.m_isFullScreen;
	rTglSurfaceCreateStruct.m_isWideViewAngle = rCreateStruct.m_isWideViewAngle;
	rTglSurfaceCreateStruct.m_direct3d = rCreateStruct.m_direct3d;
	rTglSurfaceCreateStruct.m_d3dDevice = rCreateStruct.m_d3dDevice;
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////

// FUNCTION: LEGO1 0x100ab320
Lego3DManager::Lego3DManager()
{
	// Tgl things
	m_pRenderer = 0;

	m_pLego3DView = 0;
	m_pViewLODListManager = 0;
}

// FUNCTION: LEGO1 0x100ab360
Lego3DManager::~Lego3DManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ab370
BOOL Lego3DManager::Create(CreateStruct& rCreateStruct)
{
	TglSurface::CreateStruct tglSurfaceCreateStruct;
	BOOL result;

	assert(!m_pViewLODListManager);
	assert(!m_pRenderer);
	assert(!m_pLego3DView);

	m_pViewLODListManager = new ViewLODListManager;
	assert(m_pViewLODListManager);

	m_pRenderer = Tgl::CreateRenderer();
	assert(m_pRenderer);

	m_pLego3DView = new Lego3DView;

	result = InitializeCreateStruct(tglSurfaceCreateStruct, rCreateStruct);
	assert(result);

	result = m_pLego3DView->Create(tglSurfaceCreateStruct, m_pRenderer);
	assert(result);

	return result;
}

// FUNCTION: LEGO1 0x100ab460
void Lego3DManager::Destroy()
{
	delete m_pLego3DView;
	m_pLego3DView = 0;

	delete m_pRenderer;
	m_pRenderer = 0;

	delete m_pViewLODListManager;
	m_pViewLODListManager = 0;
}

// FUNCTION: LEGO1 0x100ab4b0
double Lego3DManager::Render(double p_und)
{
	assert(m_pLego3DView);

	return m_pLego3DView->Render(p_und);
}

// FUNCTION: LEGO1 0x100ab4d0
int Lego3DManager::SetFrustrum(float p_fov, float p_front, float p_back)
{
	m_pLego3DView->GetView()->SetFrustrum(p_front, p_back, p_fov);
	m_pLego3DView->GetViewManager()->SetFrustrum(p_fov, p_front, p_back);
	return 0;
}
