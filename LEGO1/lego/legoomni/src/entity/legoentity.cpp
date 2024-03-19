#include "legoentity.h"

#include "define.h"
#include "legobuildingmanager.h"
#include "legocharactermanager.h"
#include "legoplantmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "realtime/realtime.h"

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

// FUNCTION: LEGO1 0x10010650
void LegoEntity::ResetWorldTransform(MxBool p_cameraFlag)
{
	LegoWorld* world = CurrentWorld();

	if (world != NULL && world->GetCamera() != NULL) {
		m_cameraFlag = p_cameraFlag;

		if (m_cameraFlag) {
			world->GetCamera()->SetEntity(this);
			world->GetCamera()->SetWorldTransform(
				Mx3DPointFloat(0.0F, 1.25F, 0.0F),
				Mx3DPointFloat(0.0F, 0.0F, 1.0F),
				Mx3DPointFloat(0.0F, 1.0F, 0.0F)
			);
		}
		else {
			if (world->GetCamera()->GetEntity() == this) {
				world->GetCamera()->SetEntity(NULL);
				world->GetCamera()->SetWorldTransform(
					Mx3DPointFloat(0.0F, 0.0F, 0.0F),
					Mx3DPointFloat(0.0F, 0.0F, 1.0F),
					Mx3DPointFloat(0.0F, 1.0F, 0.0F)
				);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10010790
void LegoEntity::SetWorldTransform(const Vector3& p_location, const Vector3& p_direction, const Vector3& p_up)
{
	LegoWorld* world = CurrentWorld();

	if (world != NULL && world->GetCamera() != NULL) {
		m_cameraFlag = TRUE;
		world->GetCamera()->SetEntity(this);
		world->GetCamera()->SetWorldTransform(p_location, p_direction, p_up);
	}
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
			if (m_roi->GetEntity() == this) {
				m_roi->SetEntity(NULL);
			}

			CharacterManager()->FUN_10083db0(m_roi);
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
				Mx3DPointFloat(m_worldLocation[0], m_worldLocation[1], m_worldLocation[2]),
				Mx3DPointFloat(m_worldDirection[0], m_worldDirection[1], m_worldDirection[2]),
				Mx3DPointFloat(m_worldUp[0], m_worldUp[1], m_worldUp[2]),
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

// FUNCTION: LEGO1 0x100109b0
void LegoEntity::SetLocation(const Vector3& p_location, const Vector3& p_direction, const Vector3& p_up, MxBool p_und)
{
	Mx3DPointFloat direction;
	Mx3DPointFloat up;

	direction = p_direction;
	direction.Unitize();

	up = p_up;
	up.Unitize();

	m_worldLocation = p_location;
	m_worldDirection = direction;
	m_worldUp = up;

	if (m_roi != NULL) {
		MxMatrix mat;
		CalcLocalTransform(
			Mx3DPointFloat(p_location[0], p_location[1], p_location[2]),
			Mx3DPointFloat(direction[0], direction[1], direction[2]),
			Mx3DPointFloat(up[0], up[1], up[2]),
			mat
		);

		m_roi->FUN_100a46b0(mat);
		VideoManager()->Get3DManager()->GetLego3DView()->Moved(*m_roi);

		if (p_und) {
			FUN_10010c30();
		}
	}
}

// FUNCTION: LEGO1 0x10010c30
void LegoEntity::FUN_10010c30()
{
	LegoWorld* world = CurrentWorld();

	if (m_cameraFlag && world && world->GetCamera() && m_roi) {
		world->GetCamera()->FUN_100123e0(m_roi->GetLocal2World(), 1);
	}
}

// FUNCTION: LEGO1 0x10010c60
Mx3DPointFloat LegoEntity::GetWorldDirection()
{
	if (m_roi != NULL) {
		m_worldDirection =
			Mx3DPointFloat(m_roi->GetWorldDirection()[0], m_roi->GetWorldDirection()[1], m_roi->GetWorldDirection()[2]);
	}

	return m_worldDirection;
}

// FUNCTION: LEGO1 0x10010cf0
Mx3DPointFloat LegoEntity::GetWorldUp()
{
	if (m_roi != NULL) {
		m_worldUp = Mx3DPointFloat(m_roi->GetWorldUp()[0], m_roi->GetWorldUp()[1], m_roi->GetWorldUp()[2]);
	}

	return m_worldUp;
}

// FUNCTION: LEGO1 0x10010d80
Mx3DPointFloat LegoEntity::GetWorldPosition()
{
	if (m_roi != NULL) {
		m_worldLocation =
			Mx3DPointFloat(m_roi->GetWorldPosition()[0], m_roi->GetWorldPosition()[1], m_roi->GetWorldPosition()[2]);
	}

	return m_worldLocation;
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

// FUNCTION: LEGO1 0x10010f10
void LegoEntity::VTable0x34(MxBool p_und)
{
	if (!GetUnknown0x10IsSet(c_altBit1)) {
		MxU32 objectId = 0;
		const LegoChar* roiName = m_roi->GetName();

		switch (m_unk0x59) {
		case 0:
			objectId = CharacterManager()->FUN_10085140(m_roi, p_und);
			break;
		case 1:
			break;
		case 2:
			objectId = PlantManager()->FUN_10026ba0(m_roi, p_und);
			break;
		case 3:
			objectId = BuildingManager()->FUN_1002ff40(m_roi, p_und);
			break;
		}

		if (objectId) {
			MxDSAction action;
			action.SetAtomId(MxAtomId(CharacterManager()->GetCustomizeAnimFile(), e_lowerCase2));
			action.SetObjectId(objectId);
			action.AppendData(strlen(roiName) + 1, roiName);
			Start(&action);
		}
	}
}

// STUB: LEGO1 0x10011070
void LegoEntity::VTable0x38()
{
	// TODO
}

// FUNCTION: LEGO1 0x10011300
void LegoEntity::VTable0x3c()
{
	switch (m_unk0x59) {
	case 0:
		CharacterManager()->FUN_10084ec0(m_roi);
		break;
	case 2:
		PlantManager()->FUN_100269e0(this);
		break;
	case 3:
		BuildingManager()->FUN_1002fdb0(this);
		break;
	}

	VTable0x34(FALSE);
	VTable0x38();
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
