#include "legocarbuild.h"

DECOMP_SIZE_ASSERT(LegoCarBuild, 0x34c)
DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50)

// STUB: LEGO1 0x100226d0
LegoCarBuild::LegoCarBuild()
{
	// TODO
}

// FUNCTION: LEGO1 0x10022930
MxBool LegoCarBuild::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x10022a80
LegoCarBuild::~LegoCarBuild()
{
	// TODO
}

// STUB: LEGO1 0x10022b70
MxResult LegoCarBuild::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10022fc0
void LegoCarBuild::VTable0x6c()
{
	// TODO
}

// STUB: LEGO1 0x10023020
void LegoCarBuild::VTable0x70()
{
	// TODO
}

// STUB: LEGO1 0x10023500
void LegoCarBuild::VTable0x74()
{
	// TODO
}

// STUB: LEGO1 0x10023570
void LegoCarBuild::VTable0x78()
{
	// TODO
}

// STUB: LEGO1 0x10023620
void LegoCarBuild::VTable0x7c()
{
	// TODO
}

// STUB: LEGO1 0x100236a0
void LegoCarBuild::VTable0x80()
{
	// TODO
}

// STUB: LEGO1 0x100238b0
MxResult LegoCarBuild::Tickle()
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10024050
MxLong LegoCarBuild::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x100242c0
void LegoCarBuild::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x100256c0
void LegoCarBuild::Enable(MxBool p_enable)
{
	// TODO
}

// STUB: LEGO1 0x10025e70
MxBool LegoCarBuild::Escape()
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(const char* p_classType)
{
	m_className = p_classType;
	m_unk0x4c = 0;
	m_unk0x4d = FALSE;
	m_unk0x4e = FALSE;
	m_placedPartCount = 0;
}

// FUNCTION: LEGO1 0x10026120
MxResult LegoVehicleBuildState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		Read(p_file, &m_unk0x4c);
		Read(p_file, &m_unk0x4d);
		Read(p_file, &m_unk0x4e);
		Read(p_file, &m_placedPartCount);
	}
	else {
		Write(p_file, m_unk0x4c);
		Write(p_file, m_unk0x4d);
		Write(p_file, m_unk0x4e);
		Write(p_file, m_placedPartCount);
	}

	return SUCCESS;
}
