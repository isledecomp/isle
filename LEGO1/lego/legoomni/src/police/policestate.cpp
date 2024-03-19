#include "policestate.h"

#include "islepathactor.h"
#include "legoomni.h"
#include "misc.h"
#include "mxdsaction.h"
#include "mxmisc.h"
#include "police.h"
#include "police_actions.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	m_unk0x0c = 0;
	m_policeScript = (rand() % 2 == 0) ? PoliceScript::c_nps002la_RunAnim : PoliceScript::c_nps001ni_RunAnim;
}

// FUNCTION: LEGO1 0x1005e990
MxResult PoliceState::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(ClassName());
	}

	if (p_legoFile->IsReadMode()) {
		p_legoFile->Read(&m_policeScript, sizeof(m_policeScript));
	}
	else {
		PoliceScript::Script policeScript = m_policeScript;
		p_legoFile->Write(&policeScript, sizeof(m_policeScript));
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005ea40
void PoliceState::FUN_1005ea40()
{
	PoliceScript::Script policeScript;

	if (m_unk0x0c == 1) {
		return;
	}

	switch (CurrentActor()->GetActorId()) {
	case 4:
		policeScript = PoliceScript::c_nps002la_RunAnim;
		m_policeScript = policeScript;
		break;
	case 5:
		policeScript = PoliceScript::c_nps001ni_RunAnim;
		m_policeScript = policeScript;
		break;
	default:
		policeScript = m_policeScript;
		m_policeScript = policeScript == PoliceScript::c_nps002la_RunAnim ? PoliceScript::c_nps001ni_RunAnim
																		  : PoliceScript::c_nps002la_RunAnim;
	}

	{
		MxDSAction action;
		action.SetObjectId(policeScript);
		action.SetAtomId(*g_policeScript);
		Start(&action);
	}

	m_unk0x0c = 1;
}
