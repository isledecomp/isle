#include "islepathactor.h"

#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legonavcontroller.h"
#include "legopathboundary.h"
#include "legoutils.h"
#include "misc.h"
#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)
DECOMP_SIZE_ASSERT(IslePathActor::SpawnLocation, 0x38)

// GLOBAL: LEGO1 0x10102b28
IslePathActor::SpawnLocation g_spawnLocations[29];

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
	case c_notificationEndAnim:
		ret = VTable0xd8((LegoEndAnimNotificationParam&) p_param);
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

// FUNCTION: LEGO1 0x1001a700
void IslePathActor::RegisterSpawnLocations()
{
	g_spawnLocations[0] = SpawnLocation(
		LegoGameState::e_pizzeriaExterior,
		g_isleScript,
		0,
		"int35",
		2,
		0.6,
		4,
		0.4,
		0x2a,
		JukeboxScript::c_Quiet_Audio
	);
	g_spawnLocations[1] = SpawnLocation(
		LegoGameState::e_unk23,
		g_isleScript,
		0,
		"edg00_49",
		1,
		0.43,
		2,
		0.6,
		0x27,
		JukeboxScript::c_Quiet_Audio
	);
	g_spawnLocations[2] = SpawnLocation(
		LegoGameState::e_unk24,
		g_isleScript,
		0,
		"edg00_191",
		2,
		0.5,
		0,
		0.55,
		0x26,
		JukeboxScript::c_Quiet_Audio
	);
	g_spawnLocations[3] = SpawnLocation(
		LegoGameState::e_unk4,
		g_isleScript,
		0,
		"int46",
		0,
		0.5,
		2,
		0.5,
		0x10,
		JukeboxScript::c_InformationCenter_Music
	);
	g_spawnLocations[4] = SpawnLocation(
		LegoGameState::e_jetraceExterior,
		g_isleScript,
		0,
		"EDG00_46",
		0,
		0.95,
		2,
		0.19,
		0x17,
		JukeboxScript::c_Beach_Music
	);
	g_spawnLocations[5] = SpawnLocation(
		LegoGameState::e_unk17,
		g_isleScript,
		0,
		"EDG00_46",
		3,
		0.625,
		2,
		0.03,
		0x18,
		JukeboxScript::c_Beach_Music
	);
	g_spawnLocations[6] = SpawnLocation(
		LegoGameState::e_jetrace2,
		g_isleScript,
		0,
		"EDG10_63",
		0,
		0.26,
		1,
		0.01,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[7] = SpawnLocation(
		LegoGameState::e_carraceExterior,
		g_isleScript,
		0,
		"INT15",
		5,
		0.65,
		1,
		0.68,
		0x33,
		JukeboxScript::c_CentralNorthRoad_Music
	);
	g_spawnLocations[8] = SpawnLocation(
		LegoGameState::e_unk20,
		g_isleScript,
		0,
		"INT16",
		4,
		0.1,
		2,
		0,
		0x34,
		JukeboxScript::c_CentralNorthRoad_Music
	);
	g_spawnLocations[9] = SpawnLocation(
		LegoGameState::e_unk21,
		g_isleScript,
		0,
		"INT62",
		2,
		0.1,
		3,
		0.7,
		0x36,
		JukeboxScript::c_CentralNorthRoad_Music
	);
	g_spawnLocations[10] = SpawnLocation(
		LegoGameState::e_garageExterior,
		g_isleScript,
		0,
		"INT24",
		0,
		0.55,
		2,
		0.71,
		0x08,
		JukeboxScript::c_GarageArea_Music
	);
	g_spawnLocations[11] = SpawnLocation(
		LegoGameState::e_unk28,
		g_isleScript,
		0,
		"INT24",
		2,
		0.73,
		4,
		0.71,
		0x0a,
		JukeboxScript::c_GarageArea_Music
	);
	g_spawnLocations[12] = SpawnLocation(
		LegoGameState::e_hospitalExterior,
		g_isleScript,
		0,
		"INT19",
		0,
		0.85,
		1,
		0.28,
		0,
		JukeboxScript::c_Hospital_Music
	);
	g_spawnLocations[13] = SpawnLocation(
		LegoGameState::e_unk31,
		g_isleScript,
		0,
		"EDG02_28",
		3,
		0.37,
		1,
		0.52,
		0x0c,
		JukeboxScript::c_Hospital_Music
	);
	g_spawnLocations[14] = SpawnLocation(
		LegoGameState::e_policeExterior,
		g_isleScript,
		0,
		"INT33",
		0,
		0.88,
		2,
		0.74,
		0x22,
		JukeboxScript::c_PoliceStation_Music
	);
	g_spawnLocations[15] = SpawnLocation(
		LegoGameState::e_unk33,
		g_isleScript,
		0,
		"EDG02_64",
		2,
		0.24,
		0,
		0.84,
		0x23,
		JukeboxScript::c_PoliceStation_Music
	);
	g_spawnLocations[16] = SpawnLocation(
		LegoGameState::e_unk40,
		g_isleScript,
		0,
		"edg02_51",
		2,
		0.63,
		3,
		0.01,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[17] = SpawnLocation(
		LegoGameState::e_unk41,
		g_isleScript,
		0,
		"edg02_51",
		2,
		0.63,
		0,
		0.4,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[18] = SpawnLocation(
		LegoGameState::e_unk43,
		g_isleScript,
		0,
		"edg02_35",
		2,
		0.8,
		0,
		0.2,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[19] = SpawnLocation(
		LegoGameState::e_unk44,
		g_isleScript,
		0,
		"EDG03_01",
		2,
		0.25,
		0,
		0.75,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[20] = SpawnLocation(
		LegoGameState::e_unk45,
		g_isleScript,
		0,
		"edg10_70",
		3,
		0.25,
		0,
		0.7,
		0x44,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[21] = SpawnLocation(
		LegoGameState::e_unk42,
		g_isleScript,
		0,
		"inv_05",
		2,
		0.75,
		0,
		0.19,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[22] = SpawnLocation(
		LegoGameState::e_unk48,
		g_act3Script,
		0,
		"edg02_51",
		2,
		0.63,
		0,
		0.4,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[23] = SpawnLocation(
		LegoGameState::e_unk49,
		g_act3Script,
		0,
		"inv_05",
		2,
		0.75,
		0,
		0.19,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[24] = SpawnLocation(
		LegoGameState::e_unk50,
		g_act2mainScript,
		0,
		"EDG02_51",
		0,
		0.64,
		1,
		0.37,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[25] = SpawnLocation(
		LegoGameState::e_unk51,
		g_isleScript,
		0,
		"edg02_32",
		0,
		0.5,
		2,
		0.5,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[26] = SpawnLocation(
		LegoGameState::e_unk52,
		g_isleScript,
		0,
		"edg02_19",
		2,
		0.5,
		0,
		0.5,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[27] = SpawnLocation(
		LegoGameState::e_unk54,
		g_isleScript,
		0,
		"int36",
		0,
		0.2,
		4,
		0.4,
		0,
		JukeboxScript::c_noneJukebox
	);
	g_spawnLocations[28] = SpawnLocation(
		LegoGameState::e_unk55,
		g_isleScript,
		0,
		"edg02_50",
		2,
		0.8,
		1,
		0.3,
		0,
		JukeboxScript::c_noneJukebox
	);
}

// STUB: LEGO1 0x1001b2a0
// FUNCTION: BETA10 0x100369c6
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
