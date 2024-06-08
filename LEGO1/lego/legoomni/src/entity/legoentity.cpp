#include "legoentity.h"

#include "3dmanager/lego3dmanager.h"
#include "define.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legocameracontroller.h"
#include "legocharactermanager.h"
#include "legoeventnotificationparam.h"
#include "legogamestate.h"
#include "legomain.h"
#include "legoplantmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxutilities.h"
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
	m_filename = NULL;
	m_unk0x10 = 0;
	m_flags = 0;
	m_actionType = Extra::ActionType::e_unknown;
	m_targetEntityId = -1;
	m_type = e_autoROI;
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

			CharacterManager()->ReleaseActor(m_roi);
		}
		else {
			VideoManager()->Get3DManager()->GetLego3DView()->Remove(*m_roi);
			delete m_roi;
		}
	}

	delete[] m_filename;
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

			m_roi->UpdateTransformationRelativeToParent(mat);
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

		m_roi->UpdateTransformationRelativeToParent(mat);
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

			m_filename = new char[strlen(token) + 1];
			strcpy(m_filename, token);

			if (m_actionType != Extra::ActionType::e_run) {
				m_targetEntityId = atoi(strtok(NULL, g_parseExtraTokens));
			}
		}
	}
}

// FUNCTION: LEGO1 0x10010f10
// FUNCTION: BETA10 0x1007ee87
void LegoEntity::ClickSound(MxBool p_und)
{
	if (!GetUnknown0x10IsSet(c_altBit1)) {
		MxU32 objectId = 0;
		const char* name = m_roi->GetName();

		switch (m_type) {
		case e_actor:
			objectId = CharacterManager()->FUN_10085140(m_roi, p_und);
			break;
		case e_unk1:
			break;
		case e_plant:
			objectId = PlantManager()->FUN_10026ba0(this, p_und);
			break;
		case e_building:
			objectId = BuildingManager()->FUN_1002ff40(this, p_und);
			break;
		}

		if (objectId) {
			MxDSAction action;
			action.SetAtomId(MxAtomId(CharacterManager()->GetCustomizeAnimFile(), e_lowerCase2));
			action.SetObjectId(objectId);
			action.AppendExtra(strlen(name) + 1, name);
			Start(&action);
		}
	}
}

// FUNCTION: LEGO1 0x10011070
// FUNCTION: BETA10 0x1007f062
void LegoEntity::ClickAnimation()
{
	if (!GetUnknown0x10IsSet(c_altBit1)) {
		MxU32 objectId = 0;
		MxDSAction action;
		const char* name = m_roi->GetName();
		char extra[1024];

		switch (m_type) {
		case e_actor:
			objectId = LegoOmni::GetInstance()->GetCharacterManager()->FUN_10085120(m_roi);
			action.SetAtomId(MxAtomId(LegoCharacterManager::GetCustomizeAnimFile(), e_lowerCase2));
			sprintf(extra, "SUBST:actor_01:%s", name);
			break;
		case e_unk1:
			break;
		case e_plant:
			objectId = LegoOmni::GetInstance()->GetPlantManager()->FUN_10026b70(this);
			action.SetAtomId(MxAtomId(LegoPlantManager::GetCustomizeAnimFile(), e_lowerCase2));
			sprintf(extra, "SUBST:bush:%s:tree:%s:flwrred:%s:palm:%s", name, name, name, name);
			break;
		case e_building:
			objectId = LegoOmni::GetInstance()->GetBuildingManager()->GetBuildingEntityId(this);
			action.SetAtomId(MxAtomId(BuildingManager()->GetCustomizeAnimFile(), e_lowerCase2));
			sprintf(extra, "SUBST:haus1:%s", name);
			break;
		case e_autoROI:
			break;
		}

		if (objectId) {
			action.SetObjectId(objectId);
			action.AppendExtra(strlen(extra) + 1, extra);
			LegoOmni::GetInstance()->GetAnimationManager()->StartEntityAction(action, this);
			m_unk0x10 |= c_altBit1;
		}
	}
}

// FUNCTION: LEGO1 0x10011300
// FUNCTION: BETA10 0x1007f35a
void LegoEntity::SwitchVariant()
{
	switch (m_type) {
	case e_actor:
		CharacterManager()->SwitchVariant(m_roi);
		break;
	case e_unk1:
		break;
	case e_plant:
		PlantManager()->SwitchVariant(this);
		break;
	case e_building:
		BuildingManager()->SwitchVariant(this);
		break;
	case e_autoROI:
		break;
	}

	ClickSound(FALSE);
	ClickAnimation();
}

// FUNCTION: LEGO1 0x10011360
// FUNCTION: BETA10 0x1007f411
void LegoEntity::SwitchSound()
{
	switch (m_type) {
	case e_actor:
		CharacterManager()->SwitchSound(m_roi);
		break;
	case e_unk1:
		break;
	case e_plant:
		PlantManager()->SwitchSound(this);
		break;
	case e_building:
		BuildingManager()->SwitchSound(this);
		break;
	case e_autoROI:
		break;
	}

	ClickSound(FALSE);
	ClickAnimation();
}

// FUNCTION: LEGO1 0x100113c0
// FUNCTION: BETA10 0x1007f4c8
void LegoEntity::SwitchMove()
{
	switch (m_type) {
	case e_actor:
		CharacterManager()->SwitchMove(m_roi);
		break;
	case e_unk1:
		break;
	case e_plant:
		PlantManager()->SwitchMove(this);
		break;
	case e_building:
		BuildingManager()->SwitchMove(this);
		break;
	case e_autoROI:
		break;
	}

	ClickSound(FALSE);
	ClickAnimation();
}

// FUNCTION: LEGO1 0x10011420
// FUNCTION: BETA10 0x1007f57f
void LegoEntity::SwitchColor(LegoROI* p_roi)
{
	switch (m_type) {
	case e_actor:
		CharacterManager()->SwitchColor(m_roi, p_roi);
		break;
	case e_unk1:
		break;
	case e_plant:
		PlantManager()->SwitchColor(this);
		break;
	case e_building:
		break;
	case e_autoROI:
		break;
	}

	ClickSound(FALSE);
	ClickAnimation();
}

// FUNCTION: LEGO1 0x10011470
// FUNCTION: BETA10 0x1007f62c
void LegoEntity::SwitchMood()
{
	switch (m_type) {
	case e_actor:
		CharacterManager()->SwitchMood(m_roi);
		break;
	case e_unk1:
		break;
	case e_plant:
		PlantManager()->SwitchMood(this);
		break;
	case e_building:
		BuildingManager()->SwitchMood(this);
		break;
	case e_autoROI:
		break;
	}

	ClickSound(TRUE);
	ClickSound(FALSE);
	ClickAnimation();
}

// FUNCTION: LEGO1 0x100114e0
// FUNCTION: BETA10 0x1007f6f0
void LegoEntity::SetType(MxU8 p_type)
{
	m_type = p_type;
}

// FUNCTION: LEGO1 0x100114f0
// FUNCTION: BETA10 0x1007f711
MxLong LegoEntity::Notify(MxParam& p_param)
{
	LegoEventNotificationParam& param = (LegoEventNotificationParam&) p_param;

	if (param.GetNotification() != c_notificationClick) {
		return 0;
	}

	if (m_actionType != Extra::e_unknown) {
		InvokeAction(m_actionType, MxAtomId(m_filename, e_lowerCase2), m_targetEntityId, this);
	}
	else {
		switch (GameState()->GetActorId()) {
		case LegoActor::c_pepper:
			if (GameState()->GetCurrentAct() != LegoGameState::e_act2 &&
				GameState()->GetCurrentAct() != LegoGameState::e_act3) {
				SwitchVariant();
			}
			break;
		case LegoActor::c_mama:
			SwitchSound();
			break;
		case LegoActor::c_papa:
			SwitchMove();
			break;
		case LegoActor::c_nick:
			SwitchColor(param.GetROI());
			break;
		case LegoActor::c_laura:
			SwitchMood();
			break;
		case LegoActor::c_brickster:
			switch (m_type) {
			case e_actor:
			case e_unk1:
				break;
			case e_plant:
				PlantManager()->FUN_10026c50(this);
				break;
			case e_building:
				BuildingManager()->FUN_10030000(this);
				break;
			case e_autoROI:
				break;
			}
		}
	}

	return 1;
}
