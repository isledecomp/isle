#include "infocenterstate.h"

#include "infocenter.h"
#include "infomain_actions.h"

DECOMP_SIZE_ASSERT(InfocenterState, 0x94);

// GLOBAL: LEGO1 0x100f76a8
InfomainScript::Script g_exitDialogueAct1[14] = {
	InfomainScript::c_iic019in_RunAnim,
	InfomainScript::c_iic020in_RunAnim,
	InfomainScript::c_iic021in_RunAnim,
	InfomainScript::c_iic022in_RunAnim,
	InfomainScript::c_iic023in_RunAnim,
	InfomainScript::c_iic024in_RunAnim,
	InfomainScript::c_iic025in_RunAnim,
	InfomainScript::c_iic026in_RunAnim,
	InfomainScript::c_iic027in_RunAnim,
	InfomainScript::c_iica28in_RunAnim,
	InfomainScript::c_iicb28in_RunAnim,
	InfomainScript::c_iicc28in_RunAnim,
	InfomainScript::c_iic029in_RunAnim,
	InfomainScript::c_iic032in_RunAnim
};

// GLOBAL: LEGO1 0x100f76e0
InfomainScript::Script g_exitDialogueAct23[6] = {
	InfomainScript::c_iic027in_RunAnim,
	InfomainScript::c_iic029in_RunAnim,
	InfomainScript::c_iic048in_RunAnim,
	InfomainScript::c_iic056in_RunAnim,
	InfomainScript::c_iicx23in_RunAnim
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f76f8
InfomainScript::Script g_returnDialogueAct1[6] = {
	InfomainScript::c_iicx26in_RunAnim,
	InfomainScript::c_iic033in_RunAnim,
	InfomainScript::c_iic034in_RunAnim,
	InfomainScript::c_iic035in_RunAnim,
	InfomainScript::c_iic036in_RunAnim
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7710
InfomainScript::Script g_returnDialogueAct2[4] = {
	InfomainScript::c_iic048in_RunAnim,
	InfomainScript::c_iic049in_RunAnim,
	InfomainScript::c_iic050in_RunAnim,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7720
InfomainScript::Script g_returnDialogueAct3[4] = {
	InfomainScript::c_iic055in_RunAnim,
	InfomainScript::c_iic056in_RunAnim,
	InfomainScript::c_iic057in_RunAnim,
	InfomainScript::c_iic058in_RunAnim
};

// GLOBAL: LEGO1 0x100f7730
InfomainScript::Script g_leaveDialogueAct1[4] = {
	InfomainScript::c_iic039in_PlayWav,
	InfomainScript::c_iic040in_PlayWav,
	InfomainScript::c_iic041in_PlayWav,
	InfomainScript::c_iic042in_PlayWav
};

// GLOBAL: LEGO1 0x100f7740
InfomainScript::Script g_leaveDialogueAct2[4] = {
	InfomainScript::c_iic051in_PlayWav,
	InfomainScript::c_iic052in_PlayWav,
	InfomainScript::c_iic053in_PlayWav,
	InfomainScript::c_iic054in_PlayWav
};

// GLOBAL: LEGO1 0x100f7750
InfomainScript::Script g_leaveDialogueAct3[4] = {
	InfomainScript::c_iic059in_PlayWav,
	InfomainScript::c_iic060in_PlayWav,
	InfomainScript::c_iic061in_PlayWav,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7760
InfomainScript::Script g_bricksterDialogue[2] = {
	InfomainScript::c_sbleh2br_PlayWav,
	InfomainScript::c_snshahbr_PlayWav
};

// FUNCTION: LEGO1 0x10071600
InfocenterState::InfocenterState()
{
	m_exitDialogueAct1 = LegoState::Playlist((MxU32*) g_exitDialogueAct1, _countof(g_exitDialogueAct1));
	m_exitDialogueAct23 = LegoState::Playlist((MxU32*) g_exitDialogueAct23, _countof(g_exitDialogueAct23) - 1);

	m_returnDialogue[LegoGameState::e_act1] =
		LegoState::Playlist((MxU32*) g_returnDialogueAct1, _countof(g_returnDialogueAct1) - 1);

	m_returnDialogue[LegoGameState::e_act2] =
		LegoState::Playlist((MxU32*) g_returnDialogueAct2, _countof(g_returnDialogueAct2) - 1);

	m_returnDialogue[LegoGameState::e_act3] =
		LegoState::Playlist((MxU32*) g_returnDialogueAct3, _countof(g_returnDialogueAct3));

	m_leaveDialogue[LegoGameState::e_act1] =
		LegoState::Playlist((MxU32*) g_leaveDialogueAct1, _countof(g_leaveDialogueAct1));

	m_leaveDialogue[LegoGameState::e_act2] =
		LegoState::Playlist((MxU32*) g_leaveDialogueAct2, _countof(g_leaveDialogueAct2));

	m_leaveDialogue[LegoGameState::e_act3] =
		LegoState::Playlist((MxU32*) g_leaveDialogueAct3, _countof(g_leaveDialogueAct3) - 1);

	m_bricksterDialogue = LegoState::Playlist((MxU32*) g_bricksterDialogue, _countof(g_bricksterDialogue));

	memset(m_letters, 0, sizeof(m_letters));
}

// FUNCTION: LEGO1 0x10071920
InfocenterState::~InfocenterState()
{
	MxS16 i = 0;
	do {
		if (GetNameLetter(i) != NULL) {
			delete GetNameLetter(i)->GetAction();
			delete GetNameLetter(i);
		}
		i++;
	} while (i < GetMaxNameLength());
}
