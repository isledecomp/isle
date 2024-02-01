#include "infocenterstate.h"

#include "infocenter.h"

DECOMP_SIZE_ASSERT(InfocenterState, 0x94);

// GLOBAL: LEGO1 0x100f76a8
Infocenter::InfomainScript g_unk0x100f76a8[14] = {
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
Infocenter::InfomainScript g_unk0x100f76e0[6] = {
	Infocenter::c_bricksterWarningDialogue,
	Infocenter::c_newGameGuidanceDialogue,
	Infocenter::c_bricksterEscapedDialogue1,
	Infocenter::c_bricksterEscapedDialogue5,
	Infocenter::c_exitGuidanceDialogue2
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f76f8
Infocenter::InfomainScript g_unk0x100f76f8[6] = {
	Infocenter::c_returnBackGuidanceDialogue2,
	Infocenter::c_reenterInfoCenterDialogue1,
	Infocenter::c_reenterInfoCenterDialogue2,
	Infocenter::c_reenterInfoCenterDialogue3,
	Infocenter::c_reenterInfoCenterDialogue4
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7710
Infocenter::InfomainScript g_unk0x100f7710[4] = {
	Infocenter::c_bricksterEscapedDialogue1,
	Infocenter::c_bricksterEscapedDialogue2,
	Infocenter::c_bricksterEscapedDialogue3,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7720
Infocenter::InfomainScript g_unk0x100f7720[4] = {
	Infocenter::c_bricksterEscapedDialogue4,
	Infocenter::c_bricksterEscapedDialogue5,
	Infocenter::c_bricksterEscapedDialogue6,
	Infocenter::c_bricksterEscapedDialogue7
};

// GLOBAL: LEGO1 0x100f7730
Infocenter::InfomainScript g_unk0x100f7730[4] = {
	Infocenter::c_leaveInfoCenterDialogue1,
	Infocenter::c_leaveInfoCenterDialogue2,
	Infocenter::c_leaveInfoCenterDialogue3,
	Infocenter::c_leaveInfoCenterDialogue4
};

// GLOBAL: LEGO1 0x100f7740
Infocenter::InfomainScript g_unk0x100f7740[4] =
	{Infocenter::c_unk569, Infocenter::c_unk570, Infocenter::c_unk571, Infocenter::c_unk572};

// GLOBAL: LEGO1 0x100f7750
Infocenter::InfomainScript g_unk0x100f7750[4] = {
	Infocenter::c_unk566,
	Infocenter::c_unk567,
	Infocenter::c_unk568,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7760
Infocenter::InfomainScript g_unk0x100f7760[2] = {Infocenter::c_bricksterDialogue, Infocenter::c_bricksterLaughs};

// FUNCTION: LEGO1 0x10071600
InfocenterState::InfocenterState()
{
	m_unk0x08 = LegoState::Shuffle((MxU32*) g_unk0x100f76a8, sizeof(g_unk0x100f76a8) / sizeof(g_unk0x100f76a8[0]));

	m_unk0x14 = LegoState::Shuffle((MxU32*) g_unk0x100f76e0, sizeof(g_unk0x100f76e0) / sizeof(g_unk0x100f76e0[0]) - 1);

	m_unk0x20[0] =
		LegoState::Shuffle((MxU32*) g_unk0x100f76f8, sizeof(g_unk0x100f76f8) / sizeof(g_unk0x100f76f8[0]) - 1);

	m_unk0x20[1] =
		LegoState::Shuffle((MxU32*) g_unk0x100f7710, sizeof(g_unk0x100f7710) / sizeof(g_unk0x100f7710[0]) - 1);

	m_unk0x20[2] = LegoState::Shuffle((MxU32*) g_unk0x100f7720, sizeof(g_unk0x100f7720) / sizeof(g_unk0x100f7720[0]));

	m_unk0x44[0] = LegoState::Shuffle((MxU32*) g_unk0x100f7730, sizeof(g_unk0x100f7730) / sizeof(g_unk0x100f7730[0]));

	m_unk0x44[1] = LegoState::Shuffle((MxU32*) g_unk0x100f7740, sizeof(g_unk0x100f7740) / sizeof(g_unk0x100f7740[0]));

	m_unk0x44[2] =
		LegoState::Shuffle((MxU32*) g_unk0x100f7750, sizeof(g_unk0x100f7750) / sizeof(g_unk0x100f7750[0]) - 1);

	m_unk0x68 = LegoState::Shuffle((MxU32*) g_unk0x100f7760, sizeof(g_unk0x100f7760) / sizeof(g_unk0x100f7760[0]));

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
