#include "helicopter.h"

#include "act1state.h"
#include "act3.h"
#include "isle.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legoworld.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(Helicopter, 0x230)

// FUNCTION: LEGO1 0x10001e60
Helicopter::Helicopter()
{
	m_unk0x13c = 60;
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
	LegoWorld* world = GetCurrentWorld();
	SetWorld(world);
	if (world->IsA("Act3")) {
		((Act3*) GetWorld())->SetUnkown420c(this);
	}
	world = GetWorld();
	if (world)
		world->VTable0x58(this);
	GetState();
	return result;
}

// FUNCTION: LEGO1 0x10003320
void Helicopter::GetState()
{
	m_state = (HelicopterState*) GameState()->GetState("HelicopterState");
	if (!m_state)
		m_state = (HelicopterState*) GameState()->CreateState("HelicopterState");
}

// FUNCTION: LEGO1 0x10003360
void Helicopter::VTable0xe4()
{
	if (!GameState()->GetUnknown10()) {
		VTable0xe8(0x28, TRUE, 7);
	}
	IslePathActor::VTable0xe4();
	if (!GameState()->GetUnknown10()) {
		GameState()->SetUnknown424(0x3c);
		if (GetCurrentVehicle()) {
			if (GetCurrentVehicle()->IsA("IslePathActor")) {
				((IslePathActor*) GetCurrentVehicle())->VTable0xe8(0x37, TRUE, 7);
			}
		}
	}
	m_state->SetUnknown8(0);
	FUN_1003ee00(m_script, 0x16);
	FUN_1003ee00(m_script, 0x17);
	FUN_1003ee00(m_script, 0x18);
	FUN_1003ee00(m_script, 0x19);
	FUN_1003ee00(m_script, 0x1a);
	FUN_1003ee00(m_script, 0x1b);
	FUN_1003ee00(m_script, 0x1c);
	FUN_1003ee00(m_script, 0x1d);
	FUN_1003ee00(m_script, 0x1e);
	FUN_1003ee00(m_script, 0x1f);
	AnimationManager()->FUN_1005f6d0(TRUE);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10003480
MxU32 Helicopter::VTable0xcc()
{
	if (!FUN_1003ef60())
		return 1;
	if (!m_world)
		m_world = GetCurrentWorld();
	AnimationManager()->FUN_1005f6d0(FALSE);
	if (GetCurrentVehicle()) {
		if (GetCurrentVehicle()->VTable0x60() != GameState()->GetUnknownC()) {
			GetCurrentVehicle()->VTable0xe4();
		}
	}
	switch (GameState()->GetUnknown10()) {
	case 0:
		m_script = *g_isleScript;
		AnimationManager()->FUN_10064670(FALSE);
		VTable0xe8(0x29, TRUE, 7);
		((Isle*) GetCurrentWorld())->SetUnknown13c(0x3c);
		FUN_10015820(1, 0);
		TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 50, FALSE, TRUE);
		SetUnknownDC(4);
		PlayMusic(9);
		break;
	case 1:
		m_script = *g_act2mainScript;
		break;
	case 2:
		m_script = *g_act3Script;
		break;
	}
	VTable0xe0();
	InvokeAction(ExtraActionType_start, m_script, 0x15, NULL);
	GetCurrentAction().SetObjectId(-1);
	ControlManager()->Register(this);
	return 1;
}

// FUNCTION: LEGO1 0x100035e0
MxU32 Helicopter::VTable0xd4(MxType17NotificationParam& p_param)
{
	MxU32 ret = 0;
	MxAtomId script;
	switch (GameState()->GetUnknown10()) {
	case 0:
		script = *g_isleScript;
		break;
	case 1:
		script = *g_act2mainScript;
		break;
	case 2:
		script = *g_act3Script;
		break;
	}
	if (p_param.GetUnknown28() == 1) {
		switch (p_param.GetUnknown20()) {
		case 0x17:
			if (*g_act3Script == script) {
				((Act3*) GetCurrentWorld())->SetUnkown4270(2);
				TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 50, FALSE, FALSE);
			}
			else if (m_state->GetUnkown8() != 0)
				break;
			VTable0xe4();
			GameState()->SetUnknown424(0x42);
			ret = 1;
			break;
		case 0x18: {
			if (*g_act3Script == script)
				break;
			Act1State* state = (Act1State*) GameState()->GetState("Act1State");
			if (m_state->GetUnkown8() == 0) {
				state->SetUnknown18(4);
				m_state->SetUnknown8(1);
				m_world->FUN_1001fc80(this);
				InvokeAction(ExtraActionType_start, script, 0x20, NULL);
				SetUnknownDC(0);
			}
			ret = 1;
			break;
		}
		case 0x19:
			if (*g_act3Script == script)
				break;
			if (m_state->GetUnkown8() == 2) {
				m_state->SetUnknown8(3);
				m_world->FUN_1001fc80(this);
				InvokeAction(ExtraActionType_start, script, 0x21, NULL);
				SetUnknownDC(4);
			}
			ret = 1;
			break;
		case 0x1a:
			if (*g_act3Script != script)
				break;
			ret = 1;
			/* fall through */
		case 0x1b:
			if (*g_act3Script != script)
				break;
			if (m_world && m_world->GetCamera()) {
				Mx3DPointFloat loc, dir, lookat;
				loc.CopyFrom(m_world->GetCamera()->GetWorldLocation());
				dir.CopyFrom(m_world->GetCamera()->GetWorldDirection());
				lookat = dir;
				float scale = 3;
				lookat.Mul(scale);
				lookat.Add(&loc);
				Mx3DPointFloat v68, v7c, v90(0, 1, 0), va4;
				v68.CopyFrom(m_world->GetCamera()->GetWorldUp());
				va4.EqualsCross(v68, dir);
				v7c.EqualsCross(va4, v90);
				if (ret)
					if (m_world->FUN_100727e0(m_unk0x138, loc, dir, v7c))
						break;
					else if (m_world->FUN_10072980(m_unk0x138, loc, dir, v7c))
						break;
			}
			ret = 1;
			break;
		case 0x1c:
			if (GameState()->GetUnknown10() == 0) {
				((Isle*) GetCurrentWorld())->SetUnknown13c(2);
				TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 50, FALSE, FALSE);
				VTable0xe4();
			}
			ret = 1;
			break;
		case 0x1d:
			ret = 1;
			break;
		}
	}
	return ret;
}

// FUNCTION: LEGO1 0x10003c20
MxU32 Helicopter::VTable0xd8(MxType18NotificationParam& p_param)
{
	MxU32 ret = 0;

	switch (m_state->GetUnkown8()) {
	case 1: {
		if (GameState()->GetUnknown10() == 0) {
			((Act1State*) GameState()->GetState("Act1State"))->SetUnknown18(4);
			VTable0xe8(0x2a, TRUE, 7);
		}
		else
			VTable0xe8(0x31, TRUE, 7);

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

		if (GameState()->GetUnknown10() == 0) {
			((Act1State*) GameState()->GetState("Act1State"))->SetUnknown18(0);
			VTable0xe8(0x29, TRUE, 7);
		}
		else
			VTable0xe8(0x30, TRUE, 7);

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
	if (m_unk0xea != 0) {
		m_roi->FUN_100a46b0(p_transform);
		FUN_10010c30();
	}
	else {
		m_roi->FUN_100a58f0(p_transform);
		m_roi->VTable0x14();
		if (m_cameraFlag)
			FUN_10010c30();
	}
}

// FUNCTION: LEGO1 0x10003ee0
void Helicopter::VTable0x70(float p_float)
{
	MxU32 state = m_state->GetUnkown8();
	switch (state) {
	default:
		LegoPathActor::VTable0x70(p_float);
		return;
	case 4:
	case 5:
		float f = m_unk0x1f0 - p_float + 3000;
		if (f >= 0) {
			float f2 = f / 3000 + 1;
			if (f2 < 0)
				f2 = 0;
			if (1.0f < f2)
				f2 = 1.0f;
			Vector3 v(m_unk0x160[3]);
			MxMatrix mat;
			Vector3 v2(m_unk0x1a8[3]);
			float* loc = m_unk0x1a8[3];
			mat.SetIdentity();
			float fa[4];
			Vector4 v3(fa);
			if (m_unk0x1f4.FUN_100040a0(v3, f2) == SUCCESS) {
				mat.FromQuaternion(v3);
			}
			v2.SetVector(loc);
			v2.Sub(&v);
			v2.Mul(f2);
			v2.Add(&v);
			m_world->GetCamera()->FUN_100123e0(mat, 0);
		}
		else {
			if (state == 4)
				m_world->FUN_10073400();
			else
				m_world->FUN_10073430();
			m_unk0xdc = 4;
		}
	}
}

// FUNCTION: LEGO1 0x100040a0
MxResult HelicopterSubclass::FUN_100040a0(Vector4& p_v, float p_f)
{
	MxU32 state = m_unk0x30;
	if (state == 1) {
		p_v.EqualsImpl(m_unk0x0.GetData());
		p_v[3] = acos(p_v[3]) * (1 - p_f) * 2.0;
		return p_v.NormalizeQuaternion();
	}
	else if (state == 2) {
		p_v.EqualsImpl(m_unk0x18.GetData());
		p_v[3] = acos(p_v[3]) * p_f * 2.0;
		return p_v.NormalizeQuaternion();
	}
	else if (state == 3) {
		double d1 = p_v.Dot(&m_unk0x0, &m_unk0x18), d2;
		if (d1 + 1 > 0.00001) {
			if (1 - d1 > 0.00001) {
				double d = acos(d1);
				sin(d);
				d1 = sin((1 - p_f) * d) / sin(d);
				d2 = sin(p_f * d) / sin(d);
			}
			else {
				d1 = 1 - p_f;
				d2 = p_f;
			}
			for (MxS32 i = 0; i < 4; i++) {
				p_v[i] = m_unk0x18[i] * d2 + m_unk0x0[i] * d1;
			}
			return SUCCESS;
		}
		p_v[0] = -m_unk0x0[1];
		p_v[1] = m_unk0x0[1];
		p_v[2] = -m_unk0x0[3];
		p_v[3] = m_unk0x0[2];
		d1 = sin((1 - p_f) * 1.570796326794895);
		d2 = sin(p_f * 1.570796326794895);
		for (MxS32 i = 0; i < 3; i++) {
			p_v[i] = m_unk0x0[i] * d1 + p_v[i] * d2;
		}
		return SUCCESS;
	}
	else
		return FAILURE;
}
