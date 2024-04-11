#include "islepathactor.h"

#include "legoanimationmanager.h"
#include "legonavcontroller.h"
#include "legoutils.h"
#include "misc.h"
#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// FUNCTION: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
	m_world = NULL;
	m_unk0x13c = 6.0;
	m_unk0x15c = 1.0;
	m_unk0x158 = 0;
}

// FUNCTION: LEGO1 0x1001a280
MxResult IslePathActor::Create(MxDSAction& p_dsAction)
{
	return MxEntity::Create(p_dsAction);
}

// FUNCTION: LEGO1 0x1001a2a0
void IslePathActor::Destroy(MxBool p_fromDestructor)
{
	if (!p_fromDestructor) {
		LegoPathActor::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x1001a2c0
MxLong IslePathActor::Notify(MxParam& p_param)
{
	MxLong ret = 0;

	switch (((MxNotificationParam&) p_param).GetType()) {
	case c_notificationType0:
		ret = VTable0xd0();
		break;
	case c_notificationType11:
		ret = VTable0xcc();
		break;
	case c_notificationClick:
		ret = VTable0xd4((LegoControlManagerEvent&) p_param);
		break;
	case c_notificationType18:
		ret = VTable0xd8((MxType18NotificationParam&) p_param);
		break;
	case c_notificationType19:
		ret = VTable0xdc((MxType19NotificationParam&) p_param);
		break;
	}

	return ret;
}

// FUNCTION: LEGO1 0x1001a350
void IslePathActor::VTable0xe0()
{
	m_roi->SetVisibility(FALSE);
	if (CurrentActor() != this) {
		m_unk0x15c = NavController()->GetMaxLinearVel();
		m_unk0x158 = CurrentActor();
		if (m_unk0x158) {
			m_unk0x158->ResetWorldTransform(FALSE);
			m_unk0x158->SetUserNavFlag(FALSE);
		}
	}

	AnimationManager()->FUN_10061010(0);
	if (!m_cameraFlag) {
		ResetWorldTransform(TRUE);
		SetUserNavFlag(TRUE);

		NavController()->ResetLinearVel(m_unk0x13c);

		SetCurrentActor(this);
		FUN_1001b660();
		FUN_10010c30();
	}
}

// STUB: LEGO1 0x1001a3f0
void IslePathActor::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x1001b2a0
void IslePathActor::VTable0xe8(LegoGameState::Area, MxBool, MxU8)
{
	// TODO
}

// FUNCTION: LEGO1 0x1001b5b0
void IslePathActor::VTable0xec(MxMatrix p_transform, LegoPathBoundary* p_boundary, MxBool p_reset)
{
	if (m_world) {
		m_world->FUN_1001fc80(this);
		m_world->Remove(this);
		VideoManager()->Get3DManager()->GetLego3DView()->Remove(*m_roi);
	}

	m_world = CurrentWorld();
	if (p_reset) {
		VTable0xe0();
	}

	m_world->FUN_1001fa70(this);
	p_boundary->AddActor(this);
	if (m_actorId != GameState()->GetActorId()) {
		m_world->Add(this);
	}

	m_roi->FUN_100a58f0(p_transform);
	if (m_cameraFlag) {
		FUN_1003eda0();
		FUN_10010c30();
	}
}

// STUB: LEGO1 0x1001b660
void IslePathActor::FUN_1001b660()
{
	// TODO
}
