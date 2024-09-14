#include "legoact2.h"

#include "legoanimationmanager.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(LegoAct2, 0x1154)
DECOMP_SIZE_ASSERT(LegoAct2State, 0x10)

// STUB: LEGO1 0x1004fce0
// STUB: BETA10 0x1003a5a0
LegoAct2::LegoAct2()
{
	// TODO
}

// FUNCTION: LEGO1 0x1004fe10
MxBool LegoAct2::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1004fe40
// FUNCTION: BETA10 0x1003a6f0
LegoAct2::~LegoAct2()
{
	if (m_unk0x10c2) {
		TickleManager()->UnregisterClient(this);
	}

	FUN_10051900();
	InputManager()->UnRegister(this);
	if (UserActor()) {
		Remove(UserActor());
	}

	NotificationManager()->Unregister(this);
}

// STUB: LEGO1 0x1004ff20
MxResult LegoAct2::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10050040
MxResult LegoAct2::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10050380
MxLong LegoAct2::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10050a80
void LegoAct2::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10050cf0
void LegoAct2::Enable(MxBool p_enable)
{
	// TODO
}

// FUNCTION: LEGO1 0x10051900
// FUNCTION: BETA10 0x1003bed1
void LegoAct2::FUN_10051900()
{
	if (AnimationManager()) {
		AnimationManager()->Suspend();
		AnimationManager()->Resume();
		AnimationManager()->FUN_10060540(FALSE);
		AnimationManager()->FUN_100604d0(FALSE);
		AnimationManager()->EnableCamAnims(FALSE);
		AnimationManager()->FUN_1005f6d0(FALSE);
	}
}

// STUB: LEGO1 0x100519c0
void LegoAct2::VTable0x60()
{
	// TODO
}

// STUB: LEGO1 0x100519d0
MxBool LegoAct2::Escape()
{
	// TODO
	return FALSE;
}
