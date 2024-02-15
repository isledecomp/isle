#include "policestate.h"

#include "islepathactor.h"
#include "legoomni.h"
#include "mxdsaction.h"
#include "mxomni.h"
#include "police.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	m_unk0x0c = 0;
	m_action = (rand() % 2 == 0) ? Police::PoliceScript::c_lauraAnim : Police::PoliceScript::c_nickAnim;
}

// FUNCTION: LEGO1 0x1005e990
MxResult PoliceState::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(ClassName());
	}

	if (p_legoFile->IsReadMode()) {
		p_legoFile->Read(&m_action, sizeof(m_action));
	}
	else {
		undefined4 unk0x08 = m_action;
		p_legoFile->Write(&unk0x08, sizeof(m_action));
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005ea40
void PoliceState::FUN_1005ea40()
{
	MxS32 actionId;

	if (m_unk0x0c == 1)
		return;
	switch (CurrentVehicle()->VTable0x60()) {
	case 4:
		actionId = Police::PoliceScript::c_lauraAnim;
		break;
	case 5:
		actionId = Police::PoliceScript::c_nickAnim;
		break;
	default:
		actionId = m_action;
		m_action = m_action == Police::PoliceScript::c_lauraAnim ? Police::PoliceScript::c_nickAnim
																 : Police::PoliceScript::c_lauraAnim;
		goto playAction;
	}
	m_action = actionId;
playAction:
	MxDSAction action;
	action.SetObjectId(actionId);
	action.SetAtomId(*g_policeScript);
	Start(&action);
	m_unk0x0c = 1;
}
