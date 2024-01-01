#include "lego3dmanager.h"

#include "decomp.h"
#include "tgl/tgl.h"
#include "tglsurface.h"
#include "viewmanager/viewlodlist.h"

DECOMP_SIZE_ASSERT(Lego3DManager, 0x10);

// FUNCTION: LEGO1 0x100ab2d0
BOOL InitializeCreateStruct(TglSurface::CreateStruct& p_tglSurface, const Lego3DManager::CreateStruct& p_createStruct)
{
	p_tglSurface.m_unk0x00 = p_createStruct.m_unk0x00;
	p_tglSurface.m_hwnd = p_createStruct.m_hwnd;
	p_tglSurface.m_directDraw = p_createStruct.m_directDraw;
	p_tglSurface.m_ddSurface1 = p_createStruct.m_ddSurface1;
	p_tglSurface.m_ddSurface2 = p_createStruct.m_ddSurface2;
	p_tglSurface.m_ddPalette = p_createStruct.m_ddPalette;
	p_tglSurface.m_isFullScreen = p_createStruct.m_isFullScreen;
	p_tglSurface.m_flags = p_createStruct.m_flags;
	p_tglSurface.m_direct3d = p_createStruct.m_direct3d;
	p_tglSurface.m_d3dDevice = p_createStruct.m_d3dDevice;
	return TRUE;
}

// FUNCTION: LEGO1 0x100ab320
Lego3DManager::Lego3DManager()
{
	m_renderer = NULL;
	m_3dView = NULL;
	m_viewLODListManager = NULL;
}

// FUNCTION: LEGO1 0x100ab360
Lego3DManager::~Lego3DManager()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100ab370
BOOL Lego3DManager::Create(Lego3DManager::CreateStruct& p_createStruct)
{
	TglSurface::CreateStruct surfaceCreateStruct;

	m_viewLODListManager = new ViewLODListManager;
	m_renderer = Tgl::CreateRenderer();
	m_3dView = new Lego3DView;

	InitializeCreateStruct(surfaceCreateStruct, p_createStruct);

	return m_3dView->Create(surfaceCreateStruct, m_renderer);
}

// FUNCTION: LEGO1 0x100ab460
void Lego3DManager::Destroy()
{
	delete m_3dView;
	m_3dView = NULL;

	delete m_renderer;
	m_renderer = NULL;

	delete m_viewLODListManager;
	m_viewLODListManager = NULL;
}
