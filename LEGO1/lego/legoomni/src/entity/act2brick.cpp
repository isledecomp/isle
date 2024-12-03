#include "act2brick.h"

#include "legocachesoundmanager.h"
#include "legocharactermanager.h"
#include "legosoundmanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "roi/legoroi.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(Act2Brick, 0x194)

// GLOBAL: LEGO1 0x100f7a60
MxLong Act2Brick::g_lastHitActorTime = 0;

// FUNCTION: LEGO1 0x1007a2b0
// FUNCTION: BETA10 0x10012a30
Act2Brick::Act2Brick()
{
	m_whistleSound = NULL;
	m_unk0x164 = 0;
}

// FUNCTION: LEGO1 0x1007a470
Act2Brick::~Act2Brick()
{
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x1007a4e0
// STUB: BETA10 0x10012ad5
MxResult Act2Brick::FUN_1007a4e0(undefined4 p_param1)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007a620
// FUNCTION: BETA10 0x10012ba2
void Act2Brick::Remove()
{
	StopWhistleSound();
	CurrentWorld()->Remove(this);

	if (m_roi != NULL) {
		CharacterManager()->ReleaseActor(m_roi->GetName());
		m_roi = NULL;
	}

	m_unk0x164 = 0;
}

// STUB: LEGO1 0x1007a670
// STUB: BETA10 0x10012c04
void Act2Brick::FUN_1007a670(MxMatrix& p_param1, MxMatrix& p_param2, LegoPathBoundary* p_boundary)
{
	// TODO
}

// FUNCTION: LEGO1 0x1007a750
MxResult Act2Brick::VTable0x94(LegoPathActor* p_actor, MxBool)
{
	MxLong time = Timer()->GetTime();
	MxLong diff = time - g_lastHitActorTime;

	if (strcmp(p_actor->GetROI()->GetName(), "pepper")) {
		return SUCCESS;
	}

	g_lastHitActorTime = time;
	if (diff > 1000) {
		SoundManager()->GetCacheSoundManager()->Play("hitactor", NULL, FALSE);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007a7f0
// FUNCTION: BETA10 0x10012d46
MxResult Act2Brick::Tickle()
{
	MxMatrix local2world(m_roi->GetLocal2World());
	m_unk0x190++;

	if (m_unk0x190 >= 8) {
		local2world.SetTranslation(m_unk0x17c[0], m_unk0x17c[1], m_unk0x17c[2]);
		m_unk0x164 = 3;
		TickleManager()->UnregisterClient(this);
	}
	else {
		VPV3(local2world[3], local2world[3], m_unk0x168);
	}

	m_roi->FUN_100a58f0(local2world);
	m_roi->VTable0x14();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007a8c0
// FUNCTION: BETA10 0x10012ec4
MxLong Act2Brick::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == c_notificationClick && m_roi->GetVisibility()) {
		m_roi->SetVisibility(FALSE);

		if (m_whistleSound != NULL) {
			StopWhistleSound();
		}

		MxNotificationParam param(c_notificationType22, this);
		NotificationManager()->Send(CurrentWorld(), param);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1007a990
// FUNCTION: BETA10 0x10012fca
void Act2Brick::PlayWhistleSound()
{
	if (m_whistleSound == NULL) {
		m_whistleSound = SoundManager()->GetCacheSoundManager()->Play("xwhistle", m_roi->GetName(), TRUE);
	}
}

// FUNCTION: LEGO1 0x1007a9d0
// FUNCTION: BETA10 0x1001300f
void Act2Brick::StopWhistleSound()
{
	if (m_whistleSound != NULL) {
		SoundManager()->GetCacheSoundManager()->Stop(m_whistleSound);
		m_whistleSound = NULL;
	}
}

// FUNCTION: LEGO1 0x1007aa00
void Act2Brick::Mute(MxBool p_muted)
{
	if (m_whistleSound != NULL) {
		m_whistleSound->MuteSilence(p_muted);
	}
}
