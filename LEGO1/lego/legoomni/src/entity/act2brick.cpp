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

#include <assert.h>
#include <stdio.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(Act2Brick, 0x194)

// GLOBAL: LEGO1 0x100f7a38
const LegoChar* Act2Brick::g_lodNames[] =
	{"xchbase1", "xchblad1", "xchseat1", "xchtail1", "xhback1", "xhljet1", "xhmidl1", "xhmotr1", "xhsidl1", "xhsidr1"};

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

// FUNCTION: LEGO1 0x1007a4e0
// FUNCTION: BETA10 0x10012ad5
MxResult Act2Brick::Create(MxS32 p_index)
{
	if (m_roi != NULL) {
		return FAILURE;
	}

	char name[12];
	sprintf(name, "chbrick%d", p_index);

	m_roi = CharacterManager()->CreateAutoROI(name, g_lodNames[p_index], FALSE);

	BoundingSphere sphere = m_roi->GetBoundingSphere();
	sphere.Center()[1] -= 0.3;

	if (p_index < 6) {
		sphere.Radius() = m_roi->GetBoundingSphere().Radius() * 0.5f;
	}
	else {
		sphere.Radius() = m_roi->GetBoundingSphere().Radius() * 2.0f;
	}

	m_roi->SetBoundingSphere(sphere);
	m_roi->SetEntity(this);
	CurrentWorld()->Add(this);
	m_unk0x164 = 1;
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

// FUNCTION: LEGO1 0x1007a670
// FUNCTION: BETA10 0x10012c04
void Act2Brick::FUN_1007a670(MxMatrix& p_param1, MxMatrix& p_param2, LegoPathBoundary* p_boundary)
{
	m_unk0x17c = p_param2[3];
	m_unk0x168 = p_param2[3];
	m_unk0x168 -= p_param1[3];
	m_unk0x168 /= 8.0f;

	m_unk0x190 = 0;
	TickleManager()->RegisterClient(this, 20);

	m_unk0x164 = 2;
	CurrentWorld()->PlaceActor(this);
	p_boundary->AddActor(this);

	SetActorState(c_disabled);
	m_roi->FUN_100a58f0(p_param1);
	m_roi->VTable0x14();
	m_roi->SetVisibility(TRUE);
}

// FUNCTION: LEGO1 0x1007a750
MxResult Act2Brick::HitActor(LegoPathActor* p_actor, MxBool)
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
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	if (param.GetNotification() == c_notificationClick && m_roi->GetVisibility()) {
		m_roi->SetVisibility(FALSE);

		if (m_whistleSound != NULL) {
			StopWhistleSound();
		}

		MxNotificationParam param(c_notificationType22, this);
		NotificationManager()->Send(CurrentWorld(), param);
		return 1;
	}

	assert(0);
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
