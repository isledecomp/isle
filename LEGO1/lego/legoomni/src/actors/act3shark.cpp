#include "act3shark.h"

#include "act3.h"
#include "act3ammo.h"
#include "define.h"
#include "legolocomotionanimpresenter.h"
#include "misc.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(Act3Shark, 0x1a8)

// FUNCTION: LEGO1 0x10042ab0
Act3Shark::Act3Shark()
{
	m_unk0x2c = 0.0f;
	m_unk0x28 = 0;
}

// FUNCTION: LEGO1 0x10042ce0
MxResult Act3Shark::FUN_10042ce0(Act3Ammo* p_ammo)
{
	p_ammo->SetBit5(TRUE);
	m_unk0x1c.push_back(p_ammo);
	return SUCCESS;
}

// STUB: LEGO1 0x10042d40
void Act3Shark::VTable0x70(float p_time)
{
	// TODO
}

// FUNCTION: LEGO1 0x10042f30
void Act3Shark::ParseAction(char* p_extra)
{
	LegoPathActor::ParseAction(p_extra);

	m_a3 = (Act3*) CurrentWorld();

	char value[256];
	if (KeyValueStringParse(value, g_strANIMATION, p_extra)) {
		char* token = strtok(value, g_parseExtraTokens);

		while (token != NULL) {
			LegoLocomotionAnimPresenter* presenter =
				(LegoLocomotionAnimPresenter*) m_a3->Find("LegoAnimPresenter", token);

			if (presenter != NULL) {
				token = strtok(NULL, g_parseExtraTokens);

				if (token != NULL) {
					presenter->FUN_1006d680(this, atof(token));
				}
			}

			token = strtok(NULL, g_parseExtraTokens);
		}
	}

	m_a3->SetShark(this);
	m_unk0x34 = m_animMaps[0];
	m_unk0x38 = m_unk0x34->m_roiMap[1];
	m_unk0x38->SetVisibility(FALSE);
	m_a3->PlaceActor(this);
}
