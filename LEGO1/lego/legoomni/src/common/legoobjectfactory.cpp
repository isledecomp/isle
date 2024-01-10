#include "legoobjectfactory.h"

#include "carrace.h"
#include "decomp.h"
#include "dunebuggy.h"
#include "elevatorbottom.h"
#include "gasstation.h"
#include "gasstationstate.h"
#include "helicopter.h"
#include "helicopterstate.h"
#include "historybook.h"
#include "hospital.h"
#include "hospitalstate.h"
#include "infocenter.h"
#include "infocenterdoor.h"
#include "infocenterstate.h"
#include "isle.h"
#include "jetskirace.h"
#include "lego3dwavepresenter.h"
#include "legoact2.h"
#include "legoact2state.h"
#include "legoactioncontrolpresenter.h"
#include "legoactor.h"
#include "legoactorpresenter.h"
#include "legoanimactor.h"
#include "legoanimpresenter.h"
#include "legocarbuild.h"
#include "legocarbuildanimpresenter.h"
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
#include "mxvideopresenter.h"
#include "pizza.h"
#include "pizzamissionstate.h"
#include "police.h"
#include "policestate.h"
#include "registrationbook.h"
#include "score.h"
#include "scorestate.h"
#include "skateboard.h"
// #include "act2actor.h"
#include "act2brick.h"
// #include "act2genactor.h"
#include "act2policestation.h"
#include "act3.h"
#include "act3state.h"
#include "ambulance.h"
#include "ambulancemissionstate.h"
#include "bike.h"
#include "doors.h"
#include "jetski.h"
#include "legoanimmmpresenter.h"
#include "motorcycle.h"
#include "racecar.h"
#include "towtrack.h"
#include "towtrackmissionstate.h"
// #include "act3cop.h"
// #include "act3brickster.h"
#include "act1state.h"
#include "act3actor.h"
#include "act3shark.h"
#include "beachhouseentity.h"
#include "bumpbouy.h"
#include "carracestate.h"
#include "gasstationentity.h"
#include "hospitalentity.h"
#include "infocenterentity.h"
#include "jetskiracestate.h"
#include "jukeboxentity.h"
#include "pizzeria.h"
#include "pizzeriastate.h"
#include "policeentity.h"
#include "racestandsentity.h"
#include "radiostate.h"
// #include "caveentity.h"
// #include "jailentity.h"
#include "jukebox.h"
#include "jukeboxstate.h"
#include "mxcompositemediapresenter.h"
// #include "raceskel.h"
#include "animstate.h"

// TODO: Before HospitalState, add all of the different LegoVehicleBuildState's

// TODO: Uncomment once we have all the relevant types ready
// DECOMP_SIZE_ASSERT(LegoObjectFactory, 0x1c8);

// FUNCTION: LEGO1 0x10006e40
LegoObjectFactory::LegoObjectFactory()
{
#define X(V) this->m_id##V = MxAtomId(#V, LookupMode_Exact);
	FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
}

// FUNCTION: LEGO1 0x10009a90
MxCore* LegoObjectFactory::Create(const char* p_name)
{
	MxAtomId atom(p_name, LookupMode_Exact);

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
