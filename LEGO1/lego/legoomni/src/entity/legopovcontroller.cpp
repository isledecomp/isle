#include "legonavcontroller.h"
#include "legoomni.h"
#include "legopointofviewcontroller.h"
#include "mxticklemanager.h"

//////////////////////////////////////////////////////////////////////

// FUNCTION: LEGO1 0x10065550
LegoMouseController::LegoMouseController()
{
	m_isButtonDown = 0;
}

// FUNCTION: LEGO1 0x100655d0
LegoMouseController::~LegoMouseController()
{
}

// FUNCTION: LEGO1 0x10065620
void LegoMouseController::LeftDown(int p_x, int p_y)
{
	m_isButtonDown = 1;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x10065640
void LegoMouseController::LeftUp(int p_x, int p_y)
{
	m_isButtonDown = 0;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x10065660
void LegoMouseController::LeftDrag(int p_x, int p_y)
{
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x10065680
void LegoMouseController::RightDown(int p_x, int p_y)
{
	m_isButtonDown = 1;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x100656a0
void LegoMouseController::RightUp(int p_x, int p_y)
{
	m_isButtonDown = 0;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x100656c0
void LegoMouseController::RightDrag(int p_x, int p_y)
{
	m_buttonX = p_x;
	m_buttonY = p_y;
}

//////////////////////////////////////////////////////////////////////

// FUNCTION: LEGO1 0x100656e0
LegoPointOfViewController::LegoPointOfViewController()
{
	m_lego3DView = NULL;
	m_entity = NULL;
	m_nav = NULL;
	// m_entityOffsetUp is a temporary kludge.  It should be replaced
	// by 3D camera offset and position stored in the entity since each
	// entity may have a different best viewpoint.
	m_entityOffsetUp = 0.0;
}

// FUNCTION: LEGO1 0x10065770
LegoPointOfViewController::~LegoPointOfViewController()
{
	TickleManager()->UnregisterClient(this);
	if (m_nav) {
		delete m_nav;
		m_nav = NULL;
	}
}

// FUNCTION: LEGO1 0x100657f0
MxResult LegoPointOfViewController::Create(Lego3DView* p_lego3DView)
{
	m_lego3DView = p_lego3DView;
	m_nav = new LegoNavController();
	m_nav->SetTrackDefaultParams(TRUE);
	LegoOmni::GetInstance()->GetTickleManager()->RegisterClient(this, 10);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100658c0
void LegoPointOfViewController::LeftDown(int p_x, int p_y)
{
	LegoMouseController::LeftDown(p_x, p_y);
	AffectPointOfView();
}

// FUNCTION: LEGO1 0x100658e0
void LegoPointOfViewController::LeftDrag(int p_x, int p_y)
{
	LegoMouseController::LeftDrag(p_x, p_y);
	AffectPointOfView();
}

// STUB: LEGO1 0x10065900
void LegoPointOfViewController::AffectPointOfView()
{
	// TODO
}

// STUB: LEGO1 0x10065930
MxResult LegoPointOfViewController::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10065ae0
void LegoPointOfViewController::SetEntity(LegoEntity* p_entity)
{
	// TODO
}
