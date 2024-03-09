#include "act1state.h"

#include "legoutil.h"

DECOMP_SIZE_ASSERT(Act1State, 0x26c)
DECOMP_SIZE_ASSERT(Act1State::NamedPlane, 0x4c)

// GLOBAL: ISLE 0x100f37f0
MxS32 g_unk0x100f37f0[] = {
	Act1State::e_unk953,
	Act1State::e_unk954,
	Act1State::e_unk955,
};

// STUB: LEGO1 0x100334b0
Act1State::Act1State() : m_unk0x00c(0), m_unk0x00e(0), m_unk0x008(NULL), m_unk0x010(0)
{
	m_unk0x01e = 0;
	m_unk0x018 = 1;
	m_unk0x010 = 0;
	m_unk0x020 = 0;
	m_unk0x00e = 0;
	m_unk0x01f = 0;
	m_unk0x008 = g_unk0x100f37f0;
	m_unk0x014 = -1;
	m_unk0x022 = 0;
	m_unk0x154 = NULL;
	m_unk0x158 = NULL;
	m_unk0x15c = NULL;
	m_unk0x160 = NULL;
	m_unk0x1b0 = NULL;
	m_unk0x021 = 1;
	m_unk0x01c = 1;
	m_unk0x00c = _countof(g_unk0x100f37f0);
	m_unk0x1b4 = NULL;
	m_unk0x1b8 = NULL;
	m_unk0x208 = NULL;
	m_unk0x20c = NULL;
	m_unk0x25c = NULL;
	m_unk0x260 = NULL;
	m_unk0x264 = NULL;
	m_unk0x268 = NULL;
	SetFlag();
}

// FUNCTION: LEGO1 0x10033ac0
MxResult Act1State::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(ClassName());
	}

	m_unk0x024.Serialize(p_legoFile);
	m_unk0x070.Serialize(p_legoFile);
	m_unk0x0bc.Serialize(p_legoFile);
	m_unk0x108.Serialize(p_legoFile);
	m_unk0x164.Serialize(p_legoFile);
	m_unk0x1bc.Serialize(p_legoFile);
	m_unk0x210.Serialize(p_legoFile);

	if (p_legoFile->IsWriteMode()) {
		if (m_unk0x108.GetName()->Compare("") != 0) {
			if (m_unk0x154) {
				WriteNamedTexture(p_legoFile, m_unk0x154);
			}
			else {
				FUN_1003f540(p_legoFile, "chwind.gif");
			}
			if (m_unk0x158) {
				WriteNamedTexture(p_legoFile, m_unk0x158);
			}
			else {
				FUN_1003f540(p_legoFile, "chjetl.gif");
			}
			if (m_unk0x15c) {
				WriteNamedTexture(p_legoFile, m_unk0x15c);
			}
			else {
				FUN_1003f540(p_legoFile, "chjetr.gif");
			}
		}
		if (m_unk0x164.GetName()->Compare("") != 0) {
			if (m_unk0x1b0) {
				WriteNamedTexture(p_legoFile, m_unk0x1b0);
			}
			else {
				FUN_1003f540(p_legoFile, "jsfrnt.gif");
			}
			if (m_unk0x1b4) {
				WriteNamedTexture(p_legoFile, m_unk0x1b4);
			}
			else {
				FUN_1003f540(p_legoFile, "jswnsh.gif");
			}
		}
		if (m_unk0x1bc.GetName()->Compare("") != 0) {
			if (m_unk0x208) {
				WriteNamedTexture(p_legoFile, m_unk0x208);
			}
			else {
				FUN_1003f540(p_legoFile, "dbfrfn.gif");
			}
		}
		if (m_unk0x210.GetName()->Compare("") != 0) {
			if (m_unk0x25c) {
				WriteNamedTexture(p_legoFile, m_unk0x25c);
			}
			else {
				FUN_1003f540(p_legoFile, "rcfrnt.gif");
			}
			if (m_unk0x260) {
				WriteNamedTexture(p_legoFile, m_unk0x260);
			}
			else {
				FUN_1003f540(p_legoFile, "rcback.gif");
			}
			if (m_unk0x264) {
				WriteNamedTexture(p_legoFile, m_unk0x264);
			}
			else {
				FUN_1003f540(p_legoFile, "rctail.gif");
			}
		}

		p_legoFile->Write(&m_unk0x010, sizeof(undefined2));
		p_legoFile->Write(&m_unk0x022, sizeof(undefined));
	}
	else if (p_legoFile->IsReadMode()) {
		if (m_unk0x108.GetName()->Compare("") != 0) {
			m_unk0x154 = ReadNamedTexture(p_legoFile);
			if (m_unk0x154 == NULL) {
				return FAILURE;
			}

			m_unk0x158 = ReadNamedTexture(p_legoFile);
			if (m_unk0x158 == NULL) {
				return FAILURE;
			}

			m_unk0x15c = ReadNamedTexture(p_legoFile);
			if (m_unk0x15c == NULL) {
				return FAILURE;
			}
		}
		if (m_unk0x164.GetName()->Compare("") != 0) {
			m_unk0x1b0 = ReadNamedTexture(p_legoFile);
			if (m_unk0x1b0 == NULL) {
				return FAILURE;
			}

			m_unk0x1b4 = ReadNamedTexture(p_legoFile);
			if (m_unk0x1b4 == NULL) {
				return FAILURE;
			}
		}
		if (m_unk0x1bc.GetName()->Compare("") != 0) {
			m_unk0x208 = ReadNamedTexture(p_legoFile);
			if (m_unk0x208 == NULL) {
				return FAILURE;
			}
		}
		if (m_unk0x210.GetName()->Compare("") != 0) {
			m_unk0x25c = ReadNamedTexture(p_legoFile);
			if (m_unk0x25c == NULL) {
				return FAILURE;
			}

			m_unk0x260 = ReadNamedTexture(p_legoFile);
			if (m_unk0x260 == NULL) {
				return FAILURE;
			}

			m_unk0x264 = ReadNamedTexture(p_legoFile);
			if (m_unk0x264 == NULL) {
				return FAILURE;
			}
		}

		p_legoFile->Read(&m_unk0x010, sizeof(undefined2));
		p_legoFile->Read(&m_unk0x022, sizeof(undefined));
	}

	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100346d0
MxBool Act1State::SetFlag()
{
	m_unk0x024.SetName("");
	m_unk0x070.SetName("");
	m_unk0x0bc.SetName("");
	m_unk0x022 = 0;
	m_unk0x108.SetName("");

	if (m_unk0x154) {
		delete m_unk0x154;
		m_unk0x154 = NULL;
	}

	if (m_unk0x158) {
		delete m_unk0x158;
		m_unk0x158 = NULL;
	}

	if (m_unk0x15c) {
		delete m_unk0x15c;
		m_unk0x15c = NULL;
	}

	if (m_unk0x160) {
		delete m_unk0x160;
		m_unk0x160 = NULL;
	}

	m_unk0x164.SetName("");

	if (m_unk0x1b0) {
		delete m_unk0x1b0;
		m_unk0x1b0 = NULL;
	}

	if (m_unk0x1b4) {
		delete m_unk0x1b4;
		m_unk0x1b4 = NULL;
	}

	if (m_unk0x1b8) {
		delete m_unk0x1b8;
		m_unk0x1b8 = NULL;
	}

	m_unk0x1bc.SetName("");

	if (m_unk0x208) {
		delete m_unk0x208;
		m_unk0x208 = NULL;
	}

	if (m_unk0x20c) {
		delete m_unk0x20c;
		m_unk0x20c = NULL;
	}

	m_unk0x210.SetName("");

	if (m_unk0x25c) {
		delete m_unk0x25c;
		m_unk0x25c = NULL;
	}

	if (m_unk0x260) {
		delete m_unk0x260;
		m_unk0x260 = NULL;
	}

	if (m_unk0x264) {
		delete m_unk0x264;
		m_unk0x264 = NULL;
	}

	if (m_unk0x268) {
		delete m_unk0x268;
		m_unk0x268 = NULL;
	}

	return TRUE;
}

// STUB: LEGO1 0x10034d00
void Act1State::FUN_10034d00()
{
	// TODO
}
