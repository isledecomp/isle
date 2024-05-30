#include "lego3dsound.h"

#include "legocharactermanager.h"
#include "misc.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(Lego3DSound, 0x30)

// FUNCTION: LEGO1 0x10011630
Lego3DSound::Lego3DSound()
{
	Init();
}

// FUNCTION: LEGO1 0x10011670
Lego3DSound::~Lego3DSound()
{
	Destroy();
}

// FUNCTION: LEGO1 0x10011680
void Lego3DSound::Init()
{
	m_dsBuffer = NULL;
	m_unk0x0c = NULL;
	m_unk0x10 = 0;
	m_unk0x18 = 0;
	m_unk0x14 = FALSE;
	m_unk0x15 = FALSE;
	m_volume = 79;
}

// STUB: LEGO1 0x100116a0
// FUNCTION: BETA10 0x10039647
MxResult Lego3DSound::Create(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char*, MxS32 p_volume)
{
	m_volume = p_volume;

	if (MxOmni::IsSound3D()) {
		p_directSoundBuffer->QueryInterface(IID_IDirectSoundBuffer, (LPVOID*) &m_dsBuffer);
		if (m_dsBuffer == NULL) {
			return FAILURE;
		}

		// TODO
	}

	// TODO

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10011880
void Lego3DSound::Destroy()
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
undefined4 Lego3DSound::FUN_100118e0(LPDIRECTSOUNDBUFFER p_dsBuffer)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10011ca0
void Lego3DSound::FUN_10011ca0()
{
	// TODO
}

// STUB: LEGO1 0x10011cf0
MxS32 Lego3DSound::FUN_10011cf0(undefined4, undefined4)
{
	// TODO
	return 0;
}
