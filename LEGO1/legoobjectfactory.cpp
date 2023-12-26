#include "legoobjectfactory.h"

#include "decomp.h"
#include "legomodelpresenter.h"
#include "legotexturepresenter.h"
#include "legophonemepresenter.h"
#include "legoflctexturepresenter.h"
#include "legoentitypresenter.h"
#include "legoactorpresenter.h"
#include "legoworldpresenter.h"
#include "legoworld.h"
#include "legopalettepresenter.h"
#include "legopathpresenter.h"
#include "legoanimpresenter.h"
#include "legoloopinganimpresenter.h"
#include "legolocomotionanimpresenter.h"
#include "legohideanimpresenter.h"
#include "legopartpresenter.h"
#include "legocarbuildanimpresenter.h"
#include "legoactioncontrolpresenter.h"
#include "mxvideopresenter.h"
#include "legoloadcachesoundpresenter.h"
#include "lego3dwavepresenter.h"
#include "legoactor.h"
#include "legopathactor.h"
#include "legoracecar.h"
#include "legojetski.h"
#include "jetskirace.h"
#include "legoentity.h"
#include "legocarraceactor.h"
#include "legojetskiraceactor.h"
#include "legocarbuild.h"
#include "infocenter.h"
#include "legoanimactor.h"
#include "mxcontrolpresenter.h"
#include "registrationbook.h"
#include "historybook.h"
#include "elevatorbottom.h"
#include "infocenterdoor.h"
#include "score.h"
#include "scorestate.h"
#include "hospital.h"
#include "isle.h"
#include "police.h"
#include "gasstation.h"
#include "legoact2.h"
#include "legoact2state.h"
#include "carrace.h"
#include "hospitalstate.h"
#include "infocenterstate.h"
#include "policestate.h"
#include "gasstationstate.h"
#include "skateboard.h"
#include "helicopter.h"
#include "helicopterstate.h"
#include "dunebuggy.h"
#include "pizza.h"
#include "pizzamissionstate.h"
//#include "act2actor.h"
#include "act2brick.h"
//#include "act2genactor.h"
#include "act2policestation.h"
#include "act3.h"
#include "act3state.h"
#include "doors.h"
#include "legoanimmmpresenter.h"
#include "racecar.h"
#include "jetski.h"
#include "bike.h"
#include "motorcycle.h"
#include "ambulance.h"
#include "ambulancemissionstate.h"
#include "towtrack.h"
#include "towtrackmissionstate.h"
//#include "act3cop.h"
//#include "act3brickster.h"
#include "act3shark.h"
#include "bumpbouy.h"
#include "act3actor.h"
#include "jetskiracestate.h"
#include "carracestate.h"
#include "act1state.h"
#include "pizzeria.h"
#include "pizzeriastate.h"
#include "infocenterentity.h"
#include "hospitalentity.h"
#include "gasstationentity.h"
#include "policeentity.h"
#include "beachhouseentity.h"
#include "racestandsentity.h"
#include "jukeboxentity.h"
#include "radiostate.h"
//#include "caveentity.h"
//#include "jailentity.h"
#include "mxcompositemediapresenter.h"
#include "jukebox.h"
#include "jukeboxstate.h"
//#include "raceskel.h"
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
