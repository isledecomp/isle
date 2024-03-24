#include "legovariables.h"

#include "legobuildingmanager.h"
#include "legocharactermanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legoplantmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(VisibilityVariable, 0x24)
DECOMP_SIZE_ASSERT(CameraLocationVariable, 0x24)
DECOMP_SIZE_ASSERT(CursorVariable, 0x24)
DECOMP_SIZE_ASSERT(WhoAmIVariable, 0x24)
DECOMP_SIZE_ASSERT(CustomizeAnimFileVariable, 0x24)

// GLOBAL: LEGO1 0x100f39bc
// STRING: LEGO1 0x100f39a0
const char* g_varAMBULFUEL = "ambulFUEL";

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

// GLOBAL: LEGO1 0x100f3a50
// STRING: LEGO1 0x100f3a18
const char* g_delimiter2 = " \t";

// GLOBAL: LEGO1 0x100f3a54
// STRING: LEGO1 0x100f3a10
const char* g_varHIDE = "HIDE";

// GLOBAL: LEGO1 0x100f3a58
// STRING: LEGO1 0x100f3a08
const char* g_varSHOW = "SHOW";

// GLOBAL: LEGO1 0x100f3a5c
// STRING: LEGO1 0x100f3a00
const char* g_papa = "Papa";

// GLOBAL: LEGO1 0x100f3a60
// STRING: LEGO1 0x100f39f8
const char* g_mama = "Mama";

// GLOBAL: LEGO1 0x100f3a64
// STRING: LEGO1 0x100f39f0
const char* g_pepper = "Pepper";

// GLOBAL: LEGO1 0x100f3a68
// STRING: LEGO1 0x100f39e8
const char* g_nick = "Nick";

// GLOBAL: LEGO1 0x100f3a6c
// STRING: LEGO1 0x100f39e0
const char* g_laura = "Laura";

// FUNCTION: LEGO1 0x10037d00
void VisibilityVariable::SetValue(const char* p_value)
{
	MxVariable::SetValue(p_value);

	if (p_value) {
		char* instruction = strtok(m_value.GetDataPtr(), g_delimiter2);
		char* name = strtok(NULL, g_delimiter2);
		MxBool show;

		if (!strcmpi(instruction, g_varHIDE)) {
			show = FALSE;
		}
		else if (!strcmpi(instruction, g_varSHOW)) {
			show = TRUE;
		}
		else {
			return;
		}

		LegoROI* roi = FindROI(name);
		if (roi) {
			roi->SetVisibility(show);
		}
	}
}

// FUNCTION: LEGO1 0x10037d80
void CameraLocationVariable::SetValue(const char* p_value)
{
	char buffer[256];
	MxVariable::SetValue(p_value);

	strcpy(buffer, p_value);

	char* location = strtok(buffer, ",");
	NavController()->UpdateCameraLocation(location);

	location = strtok(NULL, ",");
	if (location) {
		MxFloat pov = (MxFloat) atof(location);
		VideoManager()->Get3DManager()->SetFrustrum(pov, 0.1f, 250.0f);
	}
}

// FUNCTION: LEGO1 0x10037e30
void CursorVariable::SetValue(const char* p_value)
{
}

// FUNCTION: LEGO1 0x10037e40
void WhoAmIVariable::SetValue(const char* p_value)
{
	MxVariable::SetValue(p_value);

	if (!strcmpi(p_value, g_papa)) {
		GameState()->SetActorId(3);
	}
	else if (!strcmpi(p_value, g_mama)) {
		GameState()->SetActorId(2);
	}
	else if (!strcmpi(p_value, g_pepper)) {
		GameState()->SetActorId(1);
	}
	else if (!strcmpi(p_value, g_nick)) {
		GameState()->SetActorId(4);
	}
	else if (!strcmpi(p_value, g_laura)) {
		GameState()->SetActorId(5);
	}
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
		CharacterManager()->SetCustomizeAnimFile(p_value);
		PlantManager()->SetCustomizeAnimFile(p_value);
		BuildingManager()->SetCustomizeAnimFile(p_value);
	}
}
