#include "legoworld.h"

#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxactionnotificationparam.h"
#include "mxnotificationparam.h"
#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoWorld, 0xf8);

MxBool g_isWorldActive;

// FUNCTION: LEGO1 0x100010a0
void LegoWorld::VTable0x60()
{
}

// STUB: LEGO1 0x10015820
void FUN_10015820(MxU32, MxU32)
{
	// TODO
}

// STUB: LEGO1 0x10015910
void FUN_10015910(MxU32)
{
	// TODO
}

// FUNCTION: LEGO1 0x100159c0
void SetIsWorldActive(MxBool p_isWorldActive)
{
	if (!p_isWorldActive)
		LegoOmni::GetInstance()->GetInputManager()->SetCamera(NULL);
	g_isWorldActive = p_isWorldActive;
}

// STUB: LEGO1 0x1001ca40
LegoWorld::LegoWorld()
{
	// TODO
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

// STUB: LEGO1 0x1001e0b0
MxResult LegoWorld::SetAsCurrentWorld(MxDSObject& p_dsObject)
{
	// TODO
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

// STUB: LEGO1 0x1001f630
void LegoWorld::VTable0x54()
{
	// TODO
}

// STUB: LEGO1 0x10020220
void LegoWorld::VTable0x58(MxCore* p_object)
{
	// TODO
}

// STUB: LEGO1 0x10020f10
void LegoWorld::EndAction(MxPresenter* p_presenter)
{
}

// STUB: LEGO1 0x10021a70
void LegoWorld::VTable0x68(MxBool p_add)
{
	// TODO
}

// FUNCTION: LEGO1 0x10022340
void LegoWorld::Stop()
{
	TickleManager()->UnregisterClient(this);
}
