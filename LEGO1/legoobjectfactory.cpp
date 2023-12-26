#include "legoobjectfactory.h"

#include "decomp.h"
#include "LegoModelPresenter.h"
#include "LegoTexturePresenter.h"
#include "LegoPhonemePresenter.h"
#include "LegoFlcTexturePresenter.h"
#include "LegoEntityPresenter.h"
#include "LegoActorPresenter.h"
#include "LegoWorldPresenter.h"
#include "LegoWorld.h"
#include "LegoPalettePresenter.h"
#include "LegoPathPresenter.h"
#include "LegoAnimPresenter.h"
#include "LegoLoopingAnimPresenter.h"
#include "LegoLocomotionAnimPresenter.h"
#include "LegoHideAnimPresenter.h"
#include "LegoPartPresenter.h"
#include "LegoCarBuildAnimPresenter.h"
#include "LegoActionControlPresenter.h"
#include "MxVideoPresenter.h"
#include "LegoLoadCacheSoundPresenter.h"
#include "Lego3DWavePresenter.h"
#include "LegoActor.h"
#include "LegoPathActor.h"
//#include "LegoRaceCar.h"
#include "LegoJetski.h"
#include "JetskiRace.h"
#include "LegoEntity.h"
#include "LegoCarRaceActor.h"
#include "LegoJetskiRaceActor.h"
#include "LegoCarBuild.h"
#include "Infocenter.h"
#include "LegoAnimActor.h"
#include "MxControlPresenter.h"
#include "RegistrationBook.h"
#include "HistoryBook.h"
#include "ElevatorBottom.h"
#include "InfocenterDoor.h"
#include "Score.h"
#include "ScoreState.h"
#include "Hospital.h"
#include "Isle.h"
#include "Police.h"
#include "GasStation.h"
//#include "LegoAct2.h"
#include "LegoAct2State.h"
#include "CarRace.h"
//#include "LegoRaceCarBuildState.h"
//#include "LegoCopterBuildState.h"
//#include "LegoDuneCarBuildState.h"
//#include "LegoJetskiBuildState.h"
#include "HospitalState.h"
#include "InfocenterState.h"
#include "PoliceState.h"
#include "GasStationState.h"
#include "SkateBoard.h"
#include "Helicopter.h"
#include "HelicopterState.h"
#include "DuneBuggy.h"
#include "Pizza.h"
#include "PizzaMissionState.h"
//#include "Act2Actor.h"
#include "Act2Brick.h"
//#include "Act2GenActor.h"
#include "Act2PoliceStation.h"
#include "Act3.h"
#include "Act3State.h"
#include "Doors.h"
#include "LegoAnimMMPresenter.h"
#include "RaceCar.h"
#include "Jetski.h"
#include "Bike.h"
#include "Motorcycle.h"
#include "Ambulance.h"
#include "AmbulanceMissionState.h"
#include "TowTrack.h"
#include "TowTrackMissionState.h"
//#include "Act3Cop.h"
//#include "Act3Brickster.h"
#include "Act3Shark.h"
#include "BumpBouy.h"
#include "Act3Actor.h"
#include "JetskiRaceState.h"
#include "CarRaceState.h"
#include "Act1State.h"
#include "Pizzeria.h"
#include "PizzeriaState.h"
#include "InfoCenterEntity.h"
#include "HospitalEntity.h"
#include "GasStationEntity.h"
#include "PoliceEntity.h"
#include "BeachHouseEntity.h"
#include "RaceStandsEntity.h"
#include "JukeBoxEntity.h"
#include "RadioState.h"
//#include "CaveEntity.h"
//#include "JailEntity.h"
#include "MxCompositeMediaPresenter.h"
#include "Jukebox.h"
#include "JukeBoxState.h"
//#include "RaceSkel.h"
#include "AnimState.h"

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
