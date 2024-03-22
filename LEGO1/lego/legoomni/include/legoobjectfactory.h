#ifndef LEGOOBJECTFACTORY_H
#define LEGOOBJECTFACTORY_H

#include "mxobjectfactory.h"

#define FOR_LEGOOBJECTFACTORY_OBJECTS(X)                                                                               \
	X(LegoEntityPresenter)                                                                                             \
	X(LegoActorPresenter)                                                                                              \
	X(LegoWorldPresenter)                                                                                              \
	X(LegoWorld)                                                                                                       \
	X(LegoAnimPresenter)                                                                                               \
	X(LegoModelPresenter)                                                                                              \
	X(LegoTexturePresenter)                                                                                            \
	X(LegoPhonemePresenter)                                                                                            \
	X(LegoFlcTexturePresenter)                                                                                         \
	X(LegoPalettePresenter)                                                                                            \
	X(LegoPathPresenter)                                                                                               \
	X(LegoLoopingAnimPresenter)                                                                                        \
	X(LegoLocomotionAnimPresenter)                                                                                     \
	X(LegoHideAnimPresenter)                                                                                           \
	X(LegoPartPresenter)                                                                                               \
	X(LegoCarBuildAnimPresenter)                                                                                       \
	X(LegoActionControlPresenter)                                                                                      \
	X(MxVideoPresenter)                                                                                                \
	X(LegoLoadCacheSoundPresenter)                                                                                     \
	X(Lego3DWavePresenter)                                                                                             \
	X(LegoActor)                                                                                                       \
	X(LegoPathActor)                                                                                                   \
	X(LegoRaceCar)                                                                                                     \
	X(LegoJetski)                                                                                                      \
	X(JetskiRace)                                                                                                      \
	X(LegoEntity)                                                                                                      \
	X(LegoCarRaceActor)                                                                                                \
	X(LegoJetskiRaceActor)                                                                                             \
	X(LegoCarBuild)                                                                                                    \
	X(Infocenter)                                                                                                      \
	X(LegoAnimActor)                                                                                                   \
	X(MxControlPresenter)                                                                                              \
	X(RegistrationBook)                                                                                                \
	X(HistoryBook)                                                                                                     \
	X(ElevatorBottom)                                                                                                  \
	X(InfocenterDoor)                                                                                                  \
	X(Score)                                                                                                           \
	X(ScoreState)                                                                                                      \
	X(Hospital)                                                                                                        \
	X(Isle)                                                                                                            \
	X(Police)                                                                                                          \
	X(GasStation)                                                                                                      \
	X(LegoAct2)                                                                                                        \
	X(LegoAct2State)                                                                                                   \
	X(CarRace)                                                                                                         \
	X(HospitalState)                                                                                                   \
	X(InfocenterState)                                                                                                 \
	X(PoliceState)                                                                                                     \
	X(GasStationState)                                                                                                 \
	X(SkateBoard)                                                                                                      \
	X(Helicopter)                                                                                                      \
	X(HelicopterState)                                                                                                 \
	X(DuneBuggy)                                                                                                       \
	X(Pizza)                                                                                                           \
	X(PizzaMissionState)                                                                                               \
	X(Act2Actor)                                                                                                       \
	X(Act2Brick)                                                                                                       \
	/*X(Act2GenActor)*/                                                                                                \
	X(Act2PoliceStation)                                                                                               \
	X(Act3)                                                                                                            \
	X(Act3State)                                                                                                       \
	X(Doors)                                                                                                           \
	X(LegoAnimMMPresenter)                                                                                             \
	X(RaceCar)                                                                                                         \
	X(Jetski)                                                                                                          \
	X(Bike)                                                                                                            \
	X(Motocycle)                                                                                                       \
	X(Ambulance)                                                                                                       \
	X(AmbulanceMissionState)                                                                                           \
	X(TowTrack)                                                                                                        \
	X(TowTrackMissionState)                                                                                            \
	/*X(Act3Cop)*/                                                                                                     \
	/*X(Act3Brickster)*/                                                                                               \
	X(Act3Shark)                                                                                                       \
	X(BumpBouy)                                                                                                        \
	X(Act3Actor)                                                                                                       \
	X(JetskiRaceState)                                                                                                 \
	X(CarRaceState)                                                                                                    \
	X(Act1State)                                                                                                       \
	X(Pizzeria)                                                                                                        \
	X(PizzeriaState)                                                                                                   \
	X(InfoCenterEntity)                                                                                                \
	X(HospitalEntity)                                                                                                  \
	X(GasStationEntity)                                                                                                \
	X(PoliceEntity)                                                                                                    \
	X(BeachHouseEntity)                                                                                                \
	X(RaceStandsEntity)                                                                                                \
	X(JukeBoxEntity)                                                                                                   \
	X(RadioState)                                                                                                      \
	X(CaveEntity)                                                                                                      \
	X(JailEntity)                                                                                                      \
	X(MxCompositeMediaPresenter)                                                                                       \
	X(JukeBox)                                                                                                         \
	X(JukeBoxState)                                                                                                    \
	X(RaceSkel)                                                                                                        \
	X(AnimState)

// VTABLE: LEGO1 0x100d4768
// SIZE 0x1c8
class LegoObjectFactory : public MxObjectFactory {
public:
	LegoObjectFactory();
	MxCore* Create(const char* p_name) override; // vtable+0x14
	void Destroy(MxCore* p_object) override;     // vtable+0x18

	// SYNTHETIC: LEGO1 0x10009000
	// LegoObjectFactory::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x10009170
	// LegoObjectFactory::~LegoObjectFactory

private:
#define X(V) MxAtomId m_id##V;
	FOR_LEGOOBJECTFACTORY_OBJECTS(X)
#undef X
};

#endif // LEGOOBJECTFACTORY_H
