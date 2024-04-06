#include "legounknown100d5778.h"

#include "legocharactermanager.h"
#include "misc.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(LegoUnknown100d5778, 0x30)

// FUNCTION: LEGO1 0x10011630
LegoUnknown100d5778::LegoUnknown100d5778()
{
	Init();
}

// FUNCTION: LEGO1 0x10011670
LegoUnknown100d5778::~LegoUnknown100d5778()
{
	Destroy();
}

// FUNCTION: LEGO1 0x10011680
void LegoUnknown100d5778::Init()
{
	m_dsBuffer = NULL;
	m_unk0x0c = NULL;
	m_unk0x10 = 0;
	m_unk0x18 = 0;
	m_unk0x14 = FALSE;
	m_unk0x15 = FALSE;
	m_unk0x2c = 79;
}

// STUB: LEGO1 0x100116a0
MxResult LegoUnknown100d5778::FUN_100116a0(LPDIRECTSOUND p_dsound, undefined4, undefined4 p_unk0x2c)
{
	m_unk0x2c = p_unk0x2c;

	if (MxOmni::IsSound3D()) {
		p_dsound->QueryInterface(IID_IDirectSoundBuffer, (LPVOID*) &m_dsBuffer);
		if (m_dsBuffer == NULL) {
			return FAILURE;
		}

		// TODO
	}

	// TODO

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10011880
void LegoUnknown100d5778::Destroy()
{
	if (m_dsBuffer) {
		m_dsBuffer->Release();
		m_dsBuffer = NULL;
	}

	if (m_unk0x14 && m_unk0x0c && CharacterManager()) {
		if (m_unk0x15) {
			CharacterManager()->FUN_10083db0(m_unk0x0c);
		}
		else {
			CharacterManager()->FUN_10083f10(m_unk0x0c);
		}
	}

	Init();
}

// STUB: LEGO1 0x100118e0
undefined4 LegoUnknown100d5778::FUN_100118e0(LPDIRECTSOUNDBUFFER p_dsBuffer)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10011ca0
void LegoUnknown100d5778::FUN_10011ca0()
{
	// TODO
}
