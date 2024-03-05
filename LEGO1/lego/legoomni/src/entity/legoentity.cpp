#include "legoentity.h"

#include "define.h"
#include "legoomni.h"
#include "legounksavedatawriter.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "legoworld.h"

DECOMP_SIZE_ASSERT(LegoEntity, 0x68)

// FUNCTION: LEGO1 0x100105f0
void LegoEntity::Init()
{
	m_worldLocation.Fill(0);
	m_worldDirection.Fill(0);
	m_worldSpeed = 0;
	m_roi = NULL;
	m_cameraFlag = FALSE;
	m_actionArgString = NULL;
	m_unk0x10 = 0;
	m_flags = 0;
	m_actionType = Extra::ActionType::e_unknown;
	m_actionArgNumber = -1;
	m_unk0x59 = 4;
}

// STUB: LEGO1 0x10010650
void LegoEntity::ResetWorldTransform(MxBool p_inVehicle)
{
	// TODO
}

// STUB: LEGO1 0x10010790
void LegoEntity::SetWorldTransform(const Vector3& p_loc, const Vector3& p_dir, const Vector3& p_up)
{
	// TODO
}

// FUNCTION: LEGO1 0x100107e0
MxResult LegoEntity::Create(MxDSAction& p_dsAction)
{
	m_mxEntityId = p_dsAction.GetObjectId();
	m_atom = p_dsAction.GetAtomId();
	SetWorld();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10010810
void LegoEntity::Destroy(MxBool p_fromDestructor)
{
	if (m_roi) {
		if (m_flags & c_bit1) {
			if (m_roi->GetUnknown0x104() == this) {
				m_roi->SetEntity(NULL);
			}

			UnkSaveDataWriter()->FUN_10083db0(m_roi);
		}
		else {
			VideoManager()->Get3DManager()->GetLego3DView()->Remove(*m_roi);
			delete m_roi;
		}
	}

	delete[] m_actionArgString;
	Init();
}

// FUNCTION: LEGO1 0x10010880
void LegoEntity::SetWorld()
{
	LegoWorld* world = CurrentWorld();
	if (world != NULL && world != (LegoWorld*) this) {
		world->Add(this);
	}
}

// FUNCTION: LEGO1 0x100108a0
void LegoEntity::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	m_roi = p_roi;

	if (m_roi != NULL) {
		if (p_bool2) {
			MxMatrix mat;
			CalcLocalTransform(
				Mx3DPointFloat(m_worldLocation.GetX(), m_worldLocation.GetY(), m_worldLocation.GetZ()),
				Mx3DPointFloat(m_worldDirection.GetX(), m_worldDirection.GetY(), m_worldDirection.GetZ()),
				Mx3DPointFloat(m_worldUp.GetX(), m_worldUp.GetY(), m_worldUp.GetZ()),
				mat
			);

			m_roi->FUN_100a46b0(mat);
		}

		m_roi->SetEntity(this);
		VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);

		if (p_bool1) {
			ClearFlag(c_bit1);
		}
		else {
			SetFlag(c_bit1);
		}
	}
}

// STUB: LEGO1 0x100109b0
void LegoEntity::SetLocation(const Vector3& p_location, const Vector3& p_direction, const Vector3& p_up, MxBool)
{
	// TODO
}

// FUNCTION: LEGO1 0x10010c30
void LegoEntity::FUN_10010c30()
{
	LegoWorld* world = CurrentWorld();

	if (m_cameraFlag && world && world->GetCamera() && m_roi) {
		world->GetCamera()->FUN_100123e0(m_roi->GetLocal2World(), 1);
	}
}

// FUNCTION: LEGO1 0x10010e10
void LegoEntity::ParseAction(char* p_extra)
{
	char copy[1024];
	char actionValue[1024];
	strcpy(copy, p_extra);

	if (KeyValueStringParse(actionValue, g_strACTION, copy)) {
		m_actionType = MatchActionString(strtok(actionValue, g_parseExtraTokens));

		if (m_actionType != Extra::ActionType::e_exit) {
			char* token = strtok(NULL, g_parseExtraTokens);

			m_actionArgString = new char[strlen(token) + 1];
			strcpy(m_actionArgString, token);

			if (m_actionType != Extra::ActionType::e_run) {
				m_actionArgNumber = atoi(strtok(NULL, g_parseExtraTokens));
			}
		}
	}
}

// STUB: LEGO1 0x10010f10
void LegoEntity::VTable0x34()
{
	// TODO
}

// STUB: LEGO1 0x10011070
void LegoEntity::VTable0x38()
{
	// TODO
}

// STUB: LEGO1 0x10011300
void LegoEntity::VTable0x3c()
{
	// TODO
}

// STUB: LEGO1 0x10011360
void LegoEntity::VTable0x40()
{
	// TODO
}

// STUB: LEGO1 0x100113c0
void LegoEntity::VTable0x44()
{
	// TODO
}

// STUB: LEGO1 0x10011420
void LegoEntity::VTable0x48()
{
	// TODO
}

// STUB: LEGO1 0x10011470
void LegoEntity::VTable0x4c()
{
	// TODO
}

// FUNCTION: LEGO1 0x100114e0
void LegoEntity::FUN_100114e0(MxU8 p_unk0x59)
{
	m_unk0x59 = p_unk0x59;
}

// STUB: LEGO1 0x100114f0
MxLong LegoEntity::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}
