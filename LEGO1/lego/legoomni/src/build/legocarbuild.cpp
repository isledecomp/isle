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

// STUB: LEGO1 0x10026120
MxResult LegoVehicleBuildState::Serialize(LegoFile* p_file)
{
	// TODO
	return LegoState::Serialize(p_file);
}
