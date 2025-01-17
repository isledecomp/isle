#include "legovariables.h"

#include "3dmanager/lego3dmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legovideomanager.h"
#include "misc.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(VisibilityVariable, 0x24)
DECOMP_SIZE_ASSERT(CameraLocationVariable, 0x24)
DECOMP_SIZE_ASSERT(CursorVariable, 0x24)
DECOMP_SIZE_ASSERT(WhoAmIVariable, 0x24)

// GLOBAL: LEGO1 0x100f7ab0
// STRING: LEGO1 0x100f09c0
const char* g_varJETSPEED = "jetSPEED";

// GLOBAL: LEGO1 0x100f7ab4
// STRING: LEGO1 0x100f7aa8
const char* g_varJETFUEL = "jetFUEL";

// GLOBAL: LEGO1 0x100f7658
// STRING: LEGO1 0x100f764c
const char* g_varDUNESPEED = "duneSPEED";

// GLOBAL: LEGO1 0x100f765c
// STRING: LEGO1 0x100f7640
const char* g_varDUNEFUEL = "duneFUEL";

// GLOBAL: LEGO1 0x100f3994
// STRING: LEGO1 0x100f3988
const char* g_varMOTOSPEED = "motoSPEED";

// GLOBAL: LEGO1 0x100f3998
// STRING: LEGO1 0x100f397c
const char* g_varMOTOFUEL = "motoFUEL";

// GLOBAL: LEGO1 0x100f39b8
// STRING: LEGO1 0x100f39ac
const char* g_varAMBULSPEED = "ambulSPEED";

// GLOBAL: LEGO1 0x100f39bc
// STRING: LEGO1 0x100f39a0
const char* g_varAMBULFUEL = "ambulFUEL";

// GLOBAL: LEGO1 0x100f43b0
// STRING: LEGO1 0x100f43a4
const char* g_varTOWSPEED = "towSPEED";

// GLOBAL: LEGO1 0x100f43b4
// STRING: LEGO1 0x100f439c
const char* g_varTOWFUEL = "towFUEL";

// the STRING is already declared for GLOBAL 0x101020cc
// GLOBAL: LEGO1 0x100f3a40
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

// the STRING is already declared at LEGO1 0x100f3fb0
// GLOBAL: LEGO1 0x100f3a50
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
// FUNCTION: BETA10 0x100d5620
void VisibilityVariable::SetValue(const char* p_value)
{
	MxVariable::SetValue(p_value);

	if (p_value) {
		char* instruction = strtok(m_value.GetData(), g_delimiter2);
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
	NavController()->UpdateLocation(location);

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
