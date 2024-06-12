#include "legoobjectfactory.h"

#include "act2actor.h"
#include "act2brick.h"
#include "carrace.h"
#include "decomp.h"
#include "dunebuggy.h"
#include "elevatorbottom.h"
#include "gasstation.h"
#include "helicopter.h"
#include "historybook.h"
#include "hospital.h"
#include "infocenter.h"
#include "infocenterdoor.h"
#include "isle.h"
#include "jetskirace.h"
#include "lego3dwavepresenter.h"
#include "legoact2.h"
#include "legoactioncontrolpresenter.h"
#include "legoactor.h"
#include "legoactorpresenter.h"
#include "legoanimactor.h"
#include "legoanimpresenter.h"
#include "legocarbuild.h"
#include "legocarbuildpresenter.h"
#include "legocarraceactor.h"
#include "legoentity.h"
#include "legoentitypresenter.h"
#include "legoflctexturepresenter.h"
#include "legohideanimpresenter.h"
#include "legojetski.h"
#include "legojetskiraceactor.h"
#include "legoloadcachesoundpresenter.h"
#include "legolocomotionanimpresenter.h"
#include "legoloopinganimpresenter.h"
#include "legomodelpresenter.h"
#include "legopalettepresenter.h"
#include "legopartpresenter.h"
#include "legopathactor.h"
#include "legopathpresenter.h"
#include "legophonemepresenter.h"
#include "legoracecar.h"
#include "legotexturepresenter.h"
#include "legoworld.h"
#include "legoworldpresenter.h"
#include "mxcontrolpresenter.h"
#include "pizza.h"
#include "police.h"
#include "registrationbook.h"
#include "score.h"
#include "skateboard.h"
// #include "act2genactor.h"
#include "act2policestation.h"
#include "act3.h"
#include "ambulance.h"
#include "bike.h"
#include "doors.h"
#include "jetski.h"
#include "legoanimationmanager.h"
#include "legoanimmmpresenter.h"
#include "motocycle.h"
#include "racecar.h"
#include "towtrack.h"
// #include "act3cop.h"
// #include "act3brickster.h"
#include "act3actor.h"
#include "act3shark.h"
#include "buildings.h"
#include "bumpbouy.h"
#include "caveentity.h"
#include "jukebox.h"
#include "jukeboxentity.h"
#include "legometerpresenter.h"
#include "mxcompositemediapresenter.h"
#include "pizzeria.h"
#include "raceskel.h"

// TODO: Before HospitalState, add all of the different LegoVehicleBuildState's

// TODO: Uncomment once we have all the relevant types ready
// DECOMP_SIZE_ASSERT(LegoObjectFactory, 0x1c8);

// FUNCTION: LEGO1 0x10006e40
LegoObjectFactory::LegoObjectFactory()
{
#define X(V) this->m_id##V = MxAtomId(#V, e_exact);
	FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
}

// FUNCTION: LEGO1 0x10009a90
MxCore* LegoObjectFactory::Create(const char* p_name)
{
	MxAtomId atom(p_name, e_exact);

#define X(V)                                                                                                           \
	if (this->m_id##V == atom) {                                                                                       \
		return new V;                                                                                                  \
	}                                                                                                                  \
	else
	FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
	{
		return MxObjectFactory::Create(p_name);
	}
}

// FUNCTION: LEGO1 0x1000fb30
void LegoObjectFactory::Destroy(MxCore* p_object)
{
	delete p_object;
}
