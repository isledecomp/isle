#include "3dmanager/lego3dview.h"
#include "legoentity.h"
#include "legonavcontroller.h"
#include "legoomni.h"
#include "legopointofviewcontroller.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "realtime/realtime.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(LegoMouseController, 0x20);
DECOMP_SIZE_ASSERT(LegoPointOfViewController, 0x38);

// GLOBAL: LEGO1 0x100f75ac
MxBool g_unk0x100f75ac = FALSE;

//////////////////////////////////////////////////////////////////////

// FUNCTION: LEGO1 0x10065550
LegoMouseController::LegoMouseController()
{
	m_isButtonDown = FALSE;
}

// FUNCTION: LEGO1 0x100655d0
LegoMouseController::~LegoMouseController()
{
}

// FUNCTION: LEGO1 0x10065620
void LegoMouseController::LeftDown(int p_x, int p_y)
{
	m_isButtonDown = TRUE;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x10065640
void LegoMouseController::LeftUp(int p_x, int p_y)
{
	m_isButtonDown = FALSE;
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
	m_isButtonDown = TRUE;
	m_buttonX = p_x;
	m_buttonY = p_y;
}

// FUNCTION: LEGO1 0x100656a0
void LegoMouseController::RightUp(int p_x, int p_y)
{
	m_isButtonDown = FALSE;
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
	LegoOmni::GetInstance()->SetNavController(m_nav);
	m_nav->SetTrackDefaultParams(TRUE);
	TickleManager()->RegisterClient(this, 10);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100658a0
void LegoPointOfViewController::OnViewSize(int p_width, int p_height)
{
	m_nav->SetControlMax(p_width, p_height);
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

// FUNCTION: LEGO1 0x10065900
void LegoPointOfViewController::AffectPointOfView()
{
	m_nav->SetTargets(GetButtonX(), GetButtonY(), GetIsButtonDown());
}

// FUNCTION: LEGO1 0x10065930
MxResult LegoPointOfViewController::Tickle()
{
	ViewROI* pov = m_lego3DView->GetPointOfView();

	if (pov != NULL && m_nav != NULL && m_entity == NULL) {
		Mx3DPointFloat newDir, newPos;

		Vector3 pos(pov->GetWorldPosition());
		Vector3 dir(pov->GetWorldDirection());

		if (m_nav->CalculateNewPosDir(pos, dir, newDir, newPos, NULL)) {
			MxMatrix mat;

			CalcLocalTransform(newPos, newDir, pov->GetWorldUp(), mat);
			((TimeROI*) pov)->FUN_100a9b40(mat, Timer()->GetTime());
			pov->WrappedSetLocalTransform(mat);
			m_lego3DView->Moved(*pov);

			SoundManager()->FUN_1002a410(
				pov->GetWorldPosition(),
				pov->GetWorldDirection(),
				pov->GetWorldUp(),
				pov->GetWorldVelocity()
			);

			g_unk0x100f75ac = FALSE;
		}
		else {
			if (g_unk0x100f75ac == FALSE) {
				Mx3DPointFloat vel;

				vel.Clear();
				pov->FUN_100a5a30(vel);

				SoundManager()->FUN_1002a410(
					pov->GetWorldPosition(),
					pov->GetWorldDirection(),
					pov->GetWorldUp(),
					pov->GetWorldVelocity()
				);

				g_unk0x100f75ac = TRUE;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10065ae0
void LegoPointOfViewController::SetEntity(LegoEntity* p_entity)
{
	TickleManager()->UnregisterClient(this);
	m_entity = p_entity;

	ViewROI* pov = m_lego3DView->GetPointOfView();

	if (m_entity != NULL && pov != NULL) {
		MxMatrix mat;

		CalcLocalTransform(
			Mx3DPointFloat(
				m_entity->GetWorldPosition()[0],
				m_entity->GetWorldPosition()[1] + m_entityOffsetUp,
				m_entity->GetWorldPosition()[2]
			),
			m_entity->GetWorldDirection(),
			m_entity->GetWorldUp(),
			mat
		);

		pov->WrappedSetLocalTransform(mat);
	}
	else {
		TickleManager()->RegisterClient(this, 10);
	}
}
