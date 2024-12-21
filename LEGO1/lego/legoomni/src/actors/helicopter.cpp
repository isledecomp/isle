#include "helicopter.h"

#include "act3.h"
#include "act3_actions.h"
#include "isle.h"
#include "isle_actions.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocameracontroller.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxdebug.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Helicopter, 0x230)
DECOMP_SIZE_ASSERT(HelicopterState, 0x0c)
DECOMP_SIZE_ASSERT(Mx3DPointFloat, 0x14)
DECOMP_SIZE_ASSERT(Mx4DPointFloat, 0x18)
DECOMP_SIZE_ASSERT(MxMatrix, 0x48)

// FUNCTION: LEGO1 0x10001e60
Helicopter::Helicopter()
{
	m_maxLinearVel = 60;
}

// FUNCTION: LEGO1 0x10003230
Helicopter::~Helicopter()
{
	ControlManager()->Unregister(this);
	IslePathActor::Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100032c0
MxResult Helicopter::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	m_world = CurrentWorld();
	if (m_world->IsA("Act3")) {
		((Act3*) m_world)->SetHelicopter(this);
	}

	if (m_world != NULL) {
		m_world->Add(this);
	}

	CreateState();
	return result;
}

// FUNCTION: LEGO1 0x10003320
void Helicopter::CreateState()
{
	m_state = (HelicopterState*) GameState()->GetState("HelicopterState");
	if (!m_state) {
		m_state = (HelicopterState*) GameState()->CreateState("HelicopterState");
	}
}

// FUNCTION: LEGO1 0x10003360
void Helicopter::Exit()
{
	if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
		SpawnPlayer(
			LegoGameState::e_unk40,
			TRUE,
			IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
		);
	}

	IslePathActor::Exit();

	if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
		GameState()->m_currentArea = LegoGameState::e_copter;
		if (UserActor() && UserActor()->IsA("IslePathActor")) {
			((IslePathActor*) UserActor())
				->SpawnPlayer(
					LegoGameState::e_unk55,
					TRUE,
					IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
				);
		}
	}

	m_state->SetUnknown8(0);
	RemoveFromCurrentWorld(m_script, IsleScript::c_HelicopterDashboard_Bitmap);
	RemoveFromCurrentWorld(m_script, IsleScript::c_HelicopterArms_Ctl);
	RemoveFromCurrentWorld(m_script, IsleScript::c_Helicopter_TakeOff_Ctl);
	RemoveFromCurrentWorld(m_script, IsleScript::c_Helicopter_Land_Ctl);
	RemoveFromCurrentWorld(m_script, Act3Script::c_Helicopter_Pizza_Ctl);
	RemoveFromCurrentWorld(m_script, Act3Script::c_Helicopter_Donut_Ctl);
	RemoveFromCurrentWorld(m_script, Act3Script::c_Helicopter_Info_Ctl);
	RemoveFromCurrentWorld(m_script, 0x1d);
	RemoveFromCurrentWorld(m_script, 0x1e);
	RemoveFromCurrentWorld(m_script, 0x1f);
	AnimationManager()->FUN_1005f6d0(TRUE);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10003480
MxLong Helicopter::HandleClick()
{
	if (!FUN_1003ef60()) {
		return 1;
	}

	if (!m_world) {
		m_world = CurrentWorld();
	}

	AnimationManager()->FUN_1005f6d0(FALSE);

	if (UserActor()) {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}
	}

	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::e_act1:
		m_script = *g_isleScript;
		AnimationManager()->FUN_10064670(NULL);
		SpawnPlayer(
			LegoGameState::e_unk41,
			TRUE,
			IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
		);
		((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_copter);
		FUN_10015820(TRUE, 0);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, TRUE);
		SetActorState(c_disabled);
		PlayMusic(JukeboxScript::c_Jail_Music);
		break;
	case LegoGameState::e_act2:
		m_script = *g_act2mainScript;
		break;
	case LegoGameState::e_act3:
		m_script = *g_act3Script;
		break;
	}

	Enter();
	InvokeAction(Extra::ActionType::e_start, m_script, IsleScript::c_HelicopterDashboard, NULL);
	GetCurrentAction().SetObjectId(-1);
	ControlManager()->Register(this);
	return 1;
}

// FUNCTION: LEGO1 0x100035e0
// FUNCTION: BETA10 0x1002a587
MxLong Helicopter::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;
	MxAtomId script;

	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::e_act1:
		script = *g_isleScript;
		break;
	case LegoGameState::e_act2:
		script = *g_act2mainScript;
		break;
	case LegoGameState::e_act3:
		script = *g_act3Script;
		break;
	}

	if (p_param.m_unk0x28 == 1) {
		MxU32 isPizza = FALSE;

		switch (p_param.m_clickedObjectId) {
		case IsleScript::c_HelicopterArms_Ctl:
			if (*g_act3Script == script) {
				((Act3*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}
			else if (m_state->m_unk0x08 != 0) {
				break;
			}

			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_Helicopter_TakeOff_Ctl: {
			if (*g_act3Script == script) {
				break;
			}

			Act1State* state = (Act1State*) GameState()->GetState("Act1State");
			if (m_state->m_unk0x08 == 0) {
				state->m_unk0x018 = 4;
				m_state->m_unk0x08 = 1;
				m_world->RemoveActor(this);
				InvokeAction(Extra::ActionType::e_start, script, IsleScript::c_HelicopterTakeOff_Anim, NULL);
				SetActorState(c_initial);
			}

			result = 1;
			break;
		}
		case IsleScript::c_Helicopter_Land_Ctl:
			if (*g_act3Script == script) {
				break;
			}

			if (m_state->m_unk0x08 == 2) {
				m_state->m_unk0x08 = 3;
				m_world->RemoveActor(this);
				InvokeAction(Extra::ActionType::e_start, script, IsleScript::c_HelicopterLand_Anim, NULL);
				SetActorState(c_disabled);
			}

			result = 1;
			break;
		case Act3Script::c_Helicopter_Pizza_Ctl:
			if (*g_act3Script != script) {
				break;
			}

			isPizza = TRUE;
		case Act3Script::c_Helicopter_Donut_Ctl:
			if (*g_act3Script != script) {
				break;
			}

			assert(m_pathController);

			if (m_world && m_world->GetCamera()) {
				Mx3DPointFloat location, direction, lookat;

				location = m_world->GetCamera()->GetWorldLocation();
				direction = m_world->GetCamera()->GetWorldDirection();

				lookat = direction;
				lookat *= 3.0f;
				location += lookat;

				Mx3DPointFloat v68, va4, up;
				Mx3DPointFloat v90(0, 1, 0);
				v68 = m_world->GetCamera()->GetWorldUp();
				va4.EqualsCross(&v68, &direction);
				up.EqualsCross(&va4, &v90);

				if (isPizza) {
					if (((Act3*) m_world)->ShootPizza(m_pathController, location, direction, up) != SUCCESS) {
						MxTrace("Shoot pizza failed\n");
						break;
					}
				}
				else {
					if (((Act3*) m_world)->ShootDonut(m_pathController, location, direction, up) != SUCCESS) {
						MxTrace("Shoot donut failed\n");
						break;
					}
				}
			}

			result = 1;
			break;
		/* case Act3Script::c_Helicopter_Info_Ctl: */
		case IsleScript::c_Helicopter_Info_Ctl:
			if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
				((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				Exit();
			}
			else if (*g_act3Script == script) {
				((Act3*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}

			result = 1;
			break;
		// Unknown object ID
		case 0x1d:
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10003c20
MxLong Helicopter::HandleEndAnim(LegoEndAnimNotificationParam& p_param)
{
	MxU32 ret = 0;

	switch (m_state->GetUnkown8()) {
	case 1: {
		if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
			((Act1State*) GameState()->GetState("Act1State"))->SetUnknown18(4);
			SpawnPlayer(
				LegoGameState::e_unk42,
				TRUE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
		}
		else {
			SpawnPlayer(
				LegoGameState::e_unk49,
				TRUE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
		}

		m_state->SetUnknown8(2);

		MxMatrix matrix;
		matrix.SetIdentity();

		float s = sin(0.5235987901687622); // PI / 6, 30 deg
		float c = cos(0.5235987901687622); // PI / 6, 30 deg

		float matrixCopy[4][4];
		memcpy(matrixCopy, matrix.GetData(), sizeof(matrixCopy));
		for (MxS32 i = 0; i < 4; i++) {
			matrix.GetData()[i][1] = matrixCopy[i][1] * c - matrixCopy[i][2] * s;
			matrix.GetData()[i][2] = matrixCopy[i][2] * c + matrixCopy[i][1] * s;
		}

		Vector3 at(matrix[3]), dir(matrix[2]), up(matrix[1]);
		m_world->GetCamera()->SetWorldTransform(at, dir, up);
		FUN_10010c30();
		ret = 1;
		break;
	}
	case 3: {
		MxMatrix matrix;
		matrix.SetIdentity();

		Vector3 at(matrix[3]), dir(matrix[2]), up(matrix[1]);
		at[1] = 1.25;
		m_world->GetCamera()->SetWorldTransform(at, dir, up);

		if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
			((Act1State*) GameState()->GetState("Act1State"))->SetUnknown18(0);
			SpawnPlayer(
				LegoGameState::e_unk41,
				TRUE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
		}
		else {
			SpawnPlayer(
				LegoGameState::e_unk48,
				TRUE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
		}

		m_state->SetUnknown8(0);
		ret = 1;
		break;
	}
	}

	return ret;
}

// FUNCTION: LEGO1 0x10003e90
void Helicopter::VTable0x74(Matrix4& p_transform)
{
	if (m_userNavFlag) {
		m_roi->UpdateTransformationRelativeToParent(p_transform);
		FUN_10010c30();
	}
	else {
		m_roi->FUN_100a58f0(p_transform);
		m_roi->VTable0x14();
		if (m_cameraFlag) {
			FUN_10010c30();
		}
	}
}

// FUNCTION: LEGO1 0x10003ee0
void Helicopter::Animate(float p_time)
{
	if (m_state->m_unk0x08 == 4 || m_state->m_unk0x08 == 5) {
		float f = m_unk0x1f0 - p_time + 3000.0f;
		if (f >= 0) {
			float f2 = f / -3000.0f + 1;
			if (f2 < 0) {
				f2 = 0;
			}
			if (f2 > 1.0f) {
				f2 = 1.0f;
			}

			MxMatrix mat;
			Vector3 v1(m_unk0x160[3]);
			Vector3 v2(mat[3]);
			Vector3 v3(m_unk0x1a8[3]);

			mat.SetIdentity();
			m_unk0x1f4.BETA_1004aaa0(mat, f2);

			v2 = v3;
			v2 -= v1;
			v2 *= f2;
			v2 += v1;

			m_world->GetCamera()->FUN_100123e0(mat, 0);
		}
		else {
			if (m_state->m_unk0x08 == 4) {
				((Act3*) m_world)->FUN_10073400();
			}
			else {
				((Act3*) m_world)->FUN_10073430();
			}

			LegoPathActor::m_actorState = c_disabled;
		}
	}
	else {
		LegoPathActor::Animate(p_time);
	}
}

// FUNCTION: LEGO1 0x100042a0
void Helicopter::FUN_100042a0(const Matrix4& p_matrix)
{
	MxMatrix local48;
	MxMatrix local90;

	Vector3 vec1(local48[3]);    // local98  // esp+0x30
	Vector3 vec2(local90[3]);    // localac  // esp+0x1c
	Vector3 vec3(m_unk0x1a8[0]); // locala8  // esp+0x20
	Vector3 vec4(m_unk0x1a8[1]); // localb8  // esp+0x10
	Vector3 vec5(m_unk0x1a8[2]); // EDI
	Vector3 vec6(m_unk0x1a8[3]); // locala0  // esp+0x28

	m_world->GetCamera()->FUN_100123b0(local48);
	m_unk0x1a8.SetIdentity();
	local90 = p_matrix;

	vec2[1] += 20.0f;
	vec4 = vec2;
	vec4 -= vec1;
	vec4.Unitize();

	vec5[0] = vec5[2] = 0.0f;
	vec5[1] = -1.0f;

	vec3.EqualsCross(&vec4, &vec5);
	vec3.Unitize();
	vec4.EqualsCross(&vec5, &vec3);
	vec6 = vec2;

	local90 = m_unk0x1a8;
	m_unk0x160 = local48;

	vec1.Clear();
	vec2.Clear();

	m_unk0x1f0 = Timer()->GetTime();

	m_unk0x1f4.BETA_1004a9f0(local48);
	m_unk0x1f4.FUN_10004620(local90);
	m_unk0x1f4.FUN_10004520();
}

// FUNCTION: LEGO1 0x10004640
void Helicopter::FUN_10004640(const Matrix4& p_matrix)
{
	if (m_state->m_unk0x08 != 4 && m_state->m_unk0x08 != 5) {
		m_state->m_unk0x08 = 4;
		FUN_100042a0(p_matrix);
	}
}

// FUNCTION: LEGO1 0x10004670
void Helicopter::FUN_10004670(const Matrix4& p_matrix)
{
	if (m_state->m_unk0x08 != 4 && m_state->m_unk0x08 != 5) {
		m_state->m_unk0x08 = 5;
		FUN_100042a0(p_matrix);
	}
}
