#include "legoactor.h"

DECOMP_SIZE_ASSERT(LegoActor, 0x78)

// GLOBAL: LEGO1 0x100f32d0
extern LegoChar* g_unk0x100f32d0[] = {"none", "pepper", "mama", "papa", "nick", "laura"};

// FUNCTION: LEGO1 0x1002d110
LegoActor::LegoActor()
{
	m_unk0x68 = 0.0f;
	m_sound = NULL;
	m_unk0x70 = 0.0f;
	m_unk0x10 = 0;
	m_unk0x74 = 0;
}

// FUNCTION: LEGO1 0x1002d320
LegoActor::~LegoActor()
{
	if (m_sound) {
		m_sound->FUN_10006b80();
	}
}

// STUB: LEGO1 0x1002d390
void LegoActor::ParseAction(char*)
{
	// TODO
}

// FUNCTION: LEGO1 0x1002d670
void LegoActor::SetROI(LegoROI* p_roi, MxBool p_bool1, MxBool p_bool2)
{
	const LegoChar* name;

	if (p_roi) {
		name = p_roi->GetName();
		for (int i = 1; i <= 5; i++) {
			if (strcmpi(name, g_unk0x100f32d0[i]) == 0) {
				m_unk0x59 = 0;
				m_unk0x74 = i;
				break;
			}
		}
	}

	LegoEntity::SetROI(p_roi, p_bool1, p_bool2);
}
