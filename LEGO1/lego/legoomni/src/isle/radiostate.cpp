#include "radiostate.h"

#include "jukebox.h"
#include "jukebox_actions.h"
#include "legoomni.h"
#include "mxmisc.h"
#include "mxtimer.h"

// GLOBAL: LEGO1 0x100f3218
JukeboxScript::Script g_unk0x100f3218[6] = {
	JukeboxScript::c_sns002ra_Audio,
	JukeboxScript::c_sns001ja_Audio,
	JukeboxScript::c_snsc01js_Audio,
	JukeboxScript::c_snsb01js_Audio,
	JukeboxScript::c_snsa01js_Audio,
	JukeboxScript::c_sns009ra_Audio
};

// GLOBAL: LEGO1 0x100f3230
JukeboxScript::Script g_unk0x100f3230[14] = {
	JukeboxScript::c_ham035ra_Audio,
	JukeboxScript::c_ham039ra_Audio,
	JukeboxScript::c_sns005ra_Audio,
	JukeboxScript::c_sns078pa_Audio,
	JukeboxScript::c_ham036ra_Audio,
	JukeboxScript::c_sns006ra_Audio,
	JukeboxScript::c_sns013ra_Audio,
	JukeboxScript::c_sns004ra_Audio,
	JukeboxScript::c_sns079pa_Audio,
	JukeboxScript::c_sns007ra_Audio,
	JukeboxScript::c_sns008ra_Audio,
	JukeboxScript::c_hpz037ma_Audio,
	JukeboxScript::c_sns003ra_Audio,
	JukeboxScript::c_sns010ra_Audio,
};

// GLOBAL: LEGO1 0x100f3268
JukeboxScript::Script g_unk0x100f3268[9] = {
	JukeboxScript::c_CentralRoads_Music,
	JukeboxScript::c_BeachBlvd_Music,
	JukeboxScript::c_ResidentalArea_Music,
	JukeboxScript::c_Radio1_Music,
	JukeboxScript::c_Radio2_Music,
	JukeboxScript::c_Radio3_Music,
	JukeboxScript::c_Radio4_Music,
	JukeboxScript::c_Radio5_Music,
	JukeboxScript::c_Radio6_Music,
};

// FUNCTION: LEGO1 0x1002ce10
RadioState::RadioState()
{
	srand(Timer()->GetTime());

	MxS32 random = rand();
	m_unk0x2c = random % 3;

	m_unk0x08[0] = LegoState::Playlist((MxU32*) g_unk0x100f3218, sizeof(g_unk0x100f3218) / sizeof(g_unk0x100f3218[0]));
	m_unk0x08[0].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3218) / sizeof(g_unk0x100f3218[0])));

	m_unk0x08[1] = LegoState::Playlist((MxU32*) g_unk0x100f3230, sizeof(g_unk0x100f3230) / sizeof(g_unk0x100f3230[0]));
	m_unk0x08[1].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3230) / sizeof(g_unk0x100f3230[0])));

	m_unk0x08[2] = LegoState::Playlist((MxU32*) g_unk0x100f3268, sizeof(g_unk0x100f3268) / sizeof(g_unk0x100f3268[0]));
	m_unk0x08[2].SetUnknown0x08(rand() % (sizeof(g_unk0x100f3268) / sizeof(g_unk0x100f3268[0])));

	m_active = FALSE;
}

// FUNCTION: LEGO1 0x1002cf50
MxBool RadioState::VTable0x14()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x1002d090
MxU32 RadioState::FUN_1002d090()
{
	if (m_unk0x2c == 2) {
		m_unk0x2c = 0;
	}
	else {
		m_unk0x2c++;
	}

	return m_unk0x08[m_unk0x2c].Next();
}

// FUNCTION: LEGO1 0x1002d0c0
MxBool RadioState::FUN_1002d0c0(const MxAtomId& p_atom, MxU32 p_objectId)
{
	if (*g_jukeboxScript == p_atom) {
		for (MxS16 i = 0; i < 3; i++) {
			if (m_unk0x08[i].Contains(p_objectId)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}
