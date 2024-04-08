#include "legoactor.h"

#include "define.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// GLOBAL: LEGO1 0x100f32d0
const char* g_actorNames[] = {"none", "pepper", "mama", "papa", "nick", "laura", "The_Brickster!"};

// FUNCTION: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk0x68 = 0.0f;
	m_sound = NULL;
	m_unk0x70 = 0.0f;
	m_unk0x10 = 0;
	m_actorId = 0;
}

// FUNCTION: LEGO1 0x1002d320
LegoActor::~LegoActor()
{
	if (m_sound) {
		m_sound->FUN_10006b80();
	}
}

// FUNCTION: LEGO1 0x1002d390
void LegoActor::ParseAction(char* p_extra)
{
	MxFloat speed = 0.0F;
	char value[256];
	value[0] = '\0';

	if (KeyValueStringParse(value, g_strATTACH_CAMERA, p_extra)) {
		GetROI()->SetVisibility(FALSE);

		if (value[0]) {
			Mx3DPointFloat location(0.0F, 0.0F, 0.0F);
			Mx3DPointFloat direction(0.0F, 0.0F, 1.0F);
			Mx3DPointFloat up(0.0F, 1.0F, 0.0F);

			char* token = strtok(value, g_parseExtraTokens);
			if (token != NULL) {
				location[0] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				location[1] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				location[2] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				direction[0] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				direction[1] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				direction[2] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				up[0] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				up[1] = atof(token);
			}

			token = strtok(NULL, g_parseExtraTokens);
			if (token != NULL) {
				up[2] = atof(token);
			}

			SetWorldTransform(location, direction, up);
		}
		else {
			ResetWorldTransform(TRUE);
		}
	}

	if (KeyValueStringParse(value, g_strSPEED, p_extra)) {
		speed = atof(value);
		SetWorldSpeed(speed);
	}

	if (KeyValueStringParse(value, g_strSOUND, p_extra)) {
		m_sound = SoundManager()->GetCacheSoundManager()->FUN_1003dae0(value, GetROI()->GetName(), TRUE);
	}

	if (KeyValueStringParse(value, g_strMUTE, p_extra)) {
		FUN_1002d6e0(TRUE);
	}

	if (KeyValueStringParse(value, g_strVISIBILITY, p_extra)) {
		GetROI()->SetVisibility(strcmpi(value, "FALSE") != 0);
	}
}

// FUNCTION: LEGO1 0x1002d660
const char* LegoActor::GetActorName(MxU8 p_id)
{
	return g_actorNames[p_id];
}

// FUNCTION: LEGO1 0x1002d670
void LegoActor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	if (p_roi) {
		const char* name = p_roi->GetName();

		for (MxU32 i = 1; i <= _countof(g_actorNames) - 1; i++) {
			if (!strcmpi(name, g_actorNames[i])) {
				m_unk0x59 = 0;
				m_actorId = i;
				break;
			}
		}
	}

	LegoEntity::SetROI(p_roi, p_bool1, p_bool2);
}

// STUB: LEGO1 0x1002d6e0
void LegoActor::FUN_1002d6e0(MxBool)
{
	// TODO
}
