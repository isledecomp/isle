#include "legotexturepresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

// OFFSET: LEGO1 0x1004eb40
LegoTexturePresenter::~LegoTexturePresenter()
{
	VideoManager()->RemovePresenter(*this);
}

// OFFSET: LEGO1 0x1004ebb0
MxResult LegoTexturePresenter::AddToManager()
{
	VideoManager()->AddPresenter(*this);
	return SUCCESS;
}
