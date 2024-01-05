#include "lego3dview.h"

#include "legoroi.h"
#include "tgl/tgl.h"

DECOMP_SIZE_ASSERT(Lego3DView, 0xa8)

// STUB: LEGO1 0x100aae90
Lego3DView::Lego3DView()
{
}

// STUB: LEGO1 0x100aaf30
Lego3DView::~Lego3DView()
{
}

// STUB: LEGO1 0x100aaf90
BOOL Lego3DView::Create(TglSurface::CreateStruct& p_createStruct, Tgl::Renderer* p_renderer)
{
	Tgl::DeviceDirectDrawCreateData createData = {
		p_createStruct.m_driverGUID,
		p_createStruct.m_hwnd,
		p_createStruct.m_directDraw,
		p_createStruct.m_ddSurface1,
		p_createStruct.m_ddSurface2
	};

	m_device = p_renderer->CreateDevice(createData);
	return TRUE;
}

// STUB: LEGO1 0x100ab100
void Lego3DView::FUN_100ab100(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x100ab1b0
void Lego3DView::FUN_100ab1b0(LegoROI* p_roi)
{
	// TODO
}

// STUB: LEGO1 0x100ab2b0
LegoROI* Lego3DView::PickROI(MxLong p_a, MxLong p_b)
{
	// TODO
	return NULL;
}
