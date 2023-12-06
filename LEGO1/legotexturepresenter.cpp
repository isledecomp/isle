#include "legotexturepresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

// FUNCTION: LEGO1 0x1004eb40
LegoTexturePresenter::~LegoTexturePresenter()
{
	VideoManager()->RemovePresenter(*this);
}

// FUNCTION: LEGO1 0x1004ebb0
MxResult LegoTexturePresenter::AddToManager()
{
	VideoManager()->AddPresenter(*this);
	return SUCCESS;
}
