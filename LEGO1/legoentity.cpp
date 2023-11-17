#include "legoentity.h"

#include "define.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legoworld.h"

DECOMP_SIZE_ASSERT(LegoEntity, 0x68)

// OFFSET: LEGO1 0x1000c290
LegoEntity::~LegoEntity()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100105f0
void LegoEntity::Init()
{
	m_worldLocation.Fill(0);
	m_worldDirection.Fill(0);
	m_worldSpeed = 0;
	m_roi = NULL;
	m_cameraFlag = 0;
	m_actionArgString = NULL;
	m_unk10 = 0;
	m_unk11 = 0;
	m_actionType = ExtraActionType_unknown;
	m_actionArgNumber = -1;
	m_unk59 = 4;
}

// OFFSET: LEGO1 0x10010650 STUB
void LegoEntity::ResetWorldTransform(MxBool p_inVehicle)
{
	// TODO
}

// OFFSET: LEGO1 0x10010790 STUB
void LegoEntity::SetWorldTransform(Vector3Impl& p_loc, Vector3Impl& p_dir, Vector3Impl& p_up)
{
	// TODO
}

// OFFSET: LEGO1 0x100107e0
MxResult LegoEntity::InitFromMxDSObject(MxDSObject& p_dsObject)
{
	m_mxEntityId = p_dsObject.GetObjectId();
	m_atom = p_dsObject.GetAtomId();
	Init();
	return SUCCESS;
}

// OFFSET: LEGO1 0x10010810 STUB
void LegoEntity::Destroy(MxBool p_fromDestructor)
{
	if (m_roi) {
		// TODO
	}

	delete[] m_actionArgString;
	Init();
}

// OFFSET: LEGO1 0x10010880
void LegoEntity::SetWorld()
{
	LegoWorld* world = GetCurrentWorld();
	if (world != NULL && world != (LegoWorld*) this) {
		world->VTable0x58(this);
	}
}

// OFFSET: LEGO1 0x100108a0 STUB
void LegoEntity::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	// TODO
}

// OFFSET: LEGO1 0x10010e10
void LegoEntity::ParseAction(char* p_extra)
{
	char copy[1024];
	char actionValue[1024];
	strcpy(copy, p_extra);

	if (KeyValueStringParse(actionValue, g_strACTION, copy)) {
		m_actionType = MatchActionString(strtok(actionValue, g_parseExtraTokens));

		if (m_actionType != ExtraActionType_exit) {
			char* token = strtok(NULL, g_parseExtraTokens);

			m_actionArgString = new char[strlen(token) + 1];
			strcpy(m_actionArgString, token);

			if (m_actionType != ExtraActionType_run) {
				m_actionArgNumber = atoi(strtok(NULL, g_parseExtraTokens));
			}
		}
	}
}

// OFFSET: LEGO1 0x10010f10 STUB
void LegoEntity::VTable0x34()
{
	// TODO
}

// OFFSET: LEGO1 0x10011070 STUB
void LegoEntity::VTable0x38()
{
	// TODO
}

// OFFSET: LEGO1 0x10011300 STUB
void LegoEntity::VTable0x3c()
{
	// TODO
}

// OFFSET: LEGO1 0x10011360 STUB
void LegoEntity::VTable0x40()
{
	// TODO
}

// OFFSET: LEGO1 0x100113c0 STUB
void LegoEntity::VTable0x44()
{
	// TODO
}

// OFFSET: LEGO1 0x10011420 STUB
void LegoEntity::VTable0x48()
{
	// TODO
}

// OFFSET: LEGO1 0x10011470 STUB
void LegoEntity::VTable0x4c()
{
	// TODO
}

// OFFSET: LEGO1 0x100114f0 STUB
MxLong LegoEntity::Notify(MxParam& p)
{
	// TODO

	return 0;
}
