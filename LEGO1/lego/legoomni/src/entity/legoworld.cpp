#include "legoworld.h"

#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoWorld, 0xf8)
DECOMP_SIZE_ASSERT(LegoEntityList, 0x18)
DECOMP_SIZE_ASSERT(LegoEntityListCursor, 0x10)
DECOMP_SIZE_ASSERT(MxCoreList, 0x18)
DECOMP_SIZE_ASSERT(MxCoreListCursor, 0x10)

// STUB: LEGO1 0x1001ca40
LegoWorld::LegoWorld() : m_list0x68(TRUE)
{
	// TODO
	m_worldStarted = FALSE;
	m_unk0xf4 = 4;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1001d670
MxBool LegoWorld::VTable0x5c()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x1001d680
MxBool LegoWorld::VTable0x64()
{
	return FALSE;
}

// STUB: LEGO1 0x1001dfa0
LegoWorld::~LegoWorld()
{
	// TODO
}

// FUNCTION: LEGO1 0x1001e0b0
MxResult LegoWorld::Create(MxDSAction& p_dsAction)
{
	MxEntity::Create(p_dsAction);

	m_entityList = new LegoEntityList(TRUE);

	if (!m_entityList)
		return FAILURE;

	m_coreList = new MxCoreList(TRUE);

	if (!m_coreList)
		return FAILURE;

	if (!VTable0x54())
		return FAILURE;

	if (p_dsAction.GetFlags() & MxDSAction::Flag_Enabled) {
		if (GetCurrentWorld()) {
			GetCurrentWorld()->VTable0x68(0);
		}

		SetCurrentWorld(this);
		ControlManager()->FUN_10028df0(&m_list0xb8);
	}

	SetIsWorldActive(TRUE);
	m_unk0xec = -1;

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1001f5e0
MxLong LegoWorld::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationEndAction: {
		MxPresenter* presenter = (MxPresenter*) ((MxEndActionNotificationParam&) p_param).GetSender();
		EndAction(presenter);
		ret = 1;
		break;
	}
	case c_notificationNewPresenter:
		TickleManager()->RegisterClient(this, 100);
		break;
	}
	return ret;
}

// FUNCTION: LEGO1 0x1001f630
LegoCameraController* LegoWorld::VTable0x54()
{
	MxBool success = FALSE;

	if (!VideoManager()) {
		goto done;
	}
	if (!(m_cameraController = new LegoCameraController())) {
		goto done;
	}
	if (m_cameraController->Create() != SUCCESS) {
		goto done;
	}

	m_cameraController->OnViewSize(
		VideoManager()->GetVideoParam().GetRect().GetWidth(),
		VideoManager()->GetVideoParam().GetRect().GetHeight()
	);

	success = TRUE;

done:
	if (!success) {
		if (m_cameraController) {
			delete m_cameraController;
			m_cameraController = NULL;
		}
	}

	return m_cameraController;
}

// STUB: LEGO1 0x1001fc80
void LegoWorld::FUN_1001fc80(IslePathActor* p_actor)
{
}

// STUB: LEGO1 0x10020120
MxS32 LegoWorld::GetCurrPathInfo(LegoPathBoundary** p_path, MxS32& p_value)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10020220
void LegoWorld::VTable0x58(MxCore* p_object)
{
	// TODO
}

// STUB: LEGO1 0x10020f10
void LegoWorld::EndAction(MxCore* p_object)
{
}

// STUB: LEGO1 0x10021a70
void LegoWorld::VTable0x68(MxBool p_add)
{
	// TODO
}

// FUNCTION: LEGO1 0x10022080
MxResult LegoWorld::Tickle()
{
	if (!m_worldStarted) {
		switch (m_unk0xf4) {
		case 0:
			m_worldStarted = TRUE;
			SetAppCursor(0);
			VTable0x50();
			return TRUE;
		case 2:
			if (FUN_100220e0() == 1)
				break;
		default:
			m_unk0xf4--;
		}
	}
	return TRUE;
}

// STUB: LEGO1 0x100220e0
undefined LegoWorld::FUN_100220e0()
{
	return 0;
}

// FUNCTION: LEGO1 0x10022340
void LegoWorld::VTable0x50()
{
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x100727e0
MxBool LegoWorld::FUN_100727e0(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10072980
MxBool LegoWorld::FUN_10072980(MxU32, Mx3DPointFloat& p_loc, Mx3DPointFloat& p_dir, Mx3DPointFloat& p_up)
{
	return FALSE;
}

// STUB: LEGO1 0x10073400
void LegoWorld::FUN_10073400()
{
}

// STUB: LEGO1 0x10073430
void LegoWorld::FUN_10073430()
{
}
