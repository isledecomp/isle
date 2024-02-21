#include "legovariables.h"

#include "legobuildingmanager.h"
#include "legoomni.h"
#include "legoplantmanager.h"
#include "legounksavedatawriter.h"

DECOMP_SIZE_ASSERT(VisibilityVariable, 0x24)
DECOMP_SIZE_ASSERT(CameraLocationVariable, 0x24)
DECOMP_SIZE_ASSERT(CursorVariable, 0x24)
DECOMP_SIZE_ASSERT(WhoAmIVariable, 0x24)
DECOMP_SIZE_ASSERT(CustomizeAnimFileVariable, 0x24)

// GLOBAL: LEGO1 0x100f3a40
// STRING: LEGO1 0x100f3808
const char* g_varVISIBILITY = "VISIBILITY";

// GLOBAL: LEGO1 0x100f3a44
// STRING: LEGO1 0x100f3a30
const char* g_varCAMERALOCATION = "CAMERA_LOCATION";

// GLOBAL: LEGO1 0x100f3a48
// STRING: LEGO1 0x100f3a28
const char* g_varCURSOR = "CURSOR";

// GLOBAL: LEGO1 0x100f3a4c
// STRING: LEGO1 0x100f3a1c
const char* g_varWHOAMI = "WHO_AM_I";

// STUB: LEGO1 0x10037d00
void VisibilityVariable::SetValue(const char* p_value)
{
	// TODO
}

// STUB: LEGO1 0x10037d80
void CameraLocationVariable::SetValue(const char* p_value)
{
	// TODO
}

// FUNCTION: LEGO1 0x10037e30
void CursorVariable::SetValue(const char* p_value)
{
}

// STUB: LEGO1 0x10037e40
void WhoAmIVariable::SetValue(const char* p_value)
{
	// TODO
}

// FUNCTION: LEGO1 0x10085aa0
CustomizeAnimFileVariable::CustomizeAnimFileVariable(const char* p_key)
{
	m_key = p_key;
	m_key.ToUpperCase();
}

// FUNCTION: LEGO1 0x10085b50
void CustomizeAnimFileVariable::SetValue(const char* p_value)
{
	// STRING: LEGO1 0x100fc4f4
	if (strcmp(m_key.GetData(), "CUSTOMIZE_ANIM_FILE") == 0) {
		UnkSaveDataWriter()->SetCustomizeAnimFile(p_value);
		PlantManager()->SetCustomizeAnimFile(p_value);
		BuildingManager()->SetCustomizeAnimFile(p_value);
	}
}
