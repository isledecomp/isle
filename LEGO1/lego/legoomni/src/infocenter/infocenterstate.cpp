#include "infocenterstate.h"

#include "infocenter.h"

DECOMP_SIZE_ASSERT(InfocenterState, 0x94);

// GLOBAL: LEGO1 0x100f76a8
Infocenter::InfomainScript g_exitDialogueAct1[14] = {
	Infocenter::c_clickOnObjectsGuidanceDialogue,
	Infocenter::c_arrowNavigationGuidanceDialogue,
	Infocenter::c_elevatorGuidanceDialogue,
	Infocenter::c_radioGuidanceDialogue,
	Infocenter::c_exitGuidanceDialogue1,
	Infocenter::c_goOutsideGuidanceDialogue,
	Infocenter::c_experimentGuidanceDialogue,
	Infocenter::c_returnBackGuidanceDialogue1,
	Infocenter::c_bricksterWarningDialogue,
	Infocenter::c_infomanHiccup,
	Infocenter::c_infomanSneeze,
	Infocenter::c_infomanLaughs,
	Infocenter::c_newGameGuidanceDialogue,
	Infocenter::c_returnBackGuidanceDialogue3
};

// GLOBAL: LEGO1 0x100f76e0
Infocenter::InfomainScript g_exitDialogueAct23[6] = {
	Infocenter::c_bricksterWarningDialogue,
	Infocenter::c_newGameGuidanceDialogue,
	Infocenter::c_bricksterEscapedDialogue1,
	Infocenter::c_bricksterEscapedDialogue5,
	Infocenter::c_exitGuidanceDialogue2
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f76f8
Infocenter::InfomainScript g_returnDialogueAct1[6] = {
	Infocenter::c_returnBackGuidanceDialogue2,
	Infocenter::c_reenterInfoCenterDialogue1,
	Infocenter::c_reenterInfoCenterDialogue2,
	Infocenter::c_reenterInfoCenterDialogue3,
	Infocenter::c_reenterInfoCenterDialogue4
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7710
Infocenter::InfomainScript g_returnDialogueAct2[4] = {
	Infocenter::c_bricksterEscapedDialogue1,
	Infocenter::c_bricksterEscapedDialogue2,
	Infocenter::c_bricksterEscapedDialogue3,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7720
Infocenter::InfomainScript g_returnDialogueAct3[4] = {
	Infocenter::c_bricksterEscapedDialogue4,
	Infocenter::c_bricksterEscapedDialogue5,
	Infocenter::c_bricksterEscapedDialogue6,
	Infocenter::c_bricksterEscapedDialogue7
};

// GLOBAL: LEGO1 0x100f7730
Infocenter::InfomainScript g_leaveDialogueAct1[4] = {
	Infocenter::c_leaveInfoCenterDialogue1,
	Infocenter::c_leaveInfoCenterDialogue2,
	Infocenter::c_leaveInfoCenterDialogue3,
	Infocenter::c_leaveInfoCenterDialogue4
};

// GLOBAL: LEGO1 0x100f7740
Infocenter::InfomainScript g_leaveDialogueAct2[4] =
	{Infocenter::c_unk569, Infocenter::c_unk570, Infocenter::c_unk571, Infocenter::c_unk572};

// GLOBAL: LEGO1 0x100f7750
Infocenter::InfomainScript g_leaveDialogueAct3[4] = {
	Infocenter::c_unk566,
	Infocenter::c_unk567,
	Infocenter::c_unk568,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7760
Infocenter::InfomainScript g_bricksterDialogue[2] = {Infocenter::c_bricksterDialogue, Infocenter::c_bricksterLaughs};

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

	memset(m_buffer, 0, sizeof(m_buffer));
}

// FUNCTION: LEGO1 0x10071920
InfocenterState::~InfocenterState()
{
	MxS16 i = 0;
	do {
		if (GetInfocenterBufferElement(i) != NULL) {
			delete GetInfocenterBufferElement(i)->GetAction();
			delete GetInfocenterBufferElement(i);
		}
		i++;
	} while (i < GetInfocenterBufferSize());
}
