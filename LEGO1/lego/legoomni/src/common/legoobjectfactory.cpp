// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordYM {};
class MxUnkRecordYN {};
class MxUnkRecordYO {};

#include "legoobjectfactory.h"

// Headers need to be included in a certain order to match the original binary.
// Some of the following headers were probably not directly included,
// but were included from one of the higher level classes. We should attempt
// to reverse engineer the inclusion "graph" at some point. Until then, to maintain
// correct order in the binary, we include them in the order we want here.
// clang-format off
#include "mxpresenter.h"
#include "legoentity.h"
#include "legopathactor.h"
// The below header inclusions should be sound.
#include "legoanimpresenter.h"
#include "mxcompositemediapresenter.h"
#include "legoactorpresenter.h"
#include "legomodelpresenter.h"
#include "legotexturepresenter.h"
#include "legopartpresenter.h"
#include "legoactioncontrolpresenter.h"
#include "lego3dwavepresenter.h"
#include "jetskirace.h"
#include "carrace.h"
#include "score.h"
#include "legoact2.h"
#include "helicopter.h"
#include "act2policestation.h"
#include "act3.h"
#include "doors.h"
#include "pizzeria.h"
#include "buildings.h"
#include "jukebox.h"
// clang-format on

#include "act2actor.h"
#include "act2brick.h"
#include "act2genactor.h"
#include "act2policestation.h"
#include "act3.h"
#include "act3actors.h"
#include "ambulance.h"
#include "bike.h"
#include "buildings.h"
#include "bumpbouy.h"
#include "carrace.h"
#include "decomp.h"
#include "doors.h"
#include "dunebuggy.h"
#include "elevatorbottom.h"
#include "gasstation.h"
#include "helicopter.h"
#include "historybook.h"
#include "hospital.h"
#include "infocenter.h"
#include "infocenterdoor.h"
#include "isle.h"
#include "jetski.h"
#include "jetskirace.h"
#include "jukebox.h"
#include "jukeboxentity.h"
#include "lego3dwavepresenter.h"
#include "legoact2.h"
#include "legoactioncontrolpresenter.h"
#include "legoactor.h"
#include "legoactorpresenter.h"
#include "legoanimactor.h"
#include "legoanimationmanager.h"
#include "legoanimmmpresenter.h"
#include "legoanimpresenter.h"
#include "legocarbuild.h"
#include "legocarbuildpresenter.h"
#include "legoentity.h"
#include "legoentitypresenter.h"
#include "legoflctexturepresenter.h"
#include "legoloadcachesoundpresenter.h"
#include "legometerpresenter.h"
#include "legomodelpresenter.h"
#include "legopalettepresenter.h"
#include "legopartpresenter.h"
#include "legopathactor.h"
#include "legopathpresenter.h"
#include "legophonemepresenter.h"
#include "legoracers.h"
#include "legoracespecial.h"
#include "legotexturepresenter.h"
#include "legoworld.h"
#include "legoworldpresenter.h"
#include "misc.h"
#include "motorcycle.h"
#include "mxcompositemediapresenter.h"
#include "mxcontrolpresenter.h"
#include "pizza.h"
#include "pizzeria.h"
#include "police.h"
#include "racecar.h"
#include "raceskel.h"
#include "registrationbook.h"
#include "score.h"
#include "skateboard.h"
#include "towtrack.h"

DECOMP_SIZE_ASSERT(LegoObjectFactory, 0x1c8)

// FUNCTION: LEGO1 0x10006e40
// FUNCTION: BETA10 0x1009e930
LegoObjectFactory::LegoObjectFactory()
{
	m_idLegoEntityPresenter = MxAtomId("LegoEntityPresenter", e_exact);
	m_idLegoActorPresenter = MxAtomId("LegoActorPresenter", e_exact);
	m_idLegoWorldPresenter = MxAtomId("LegoWorldPresenter", e_exact);
	m_idLegoWorld = MxAtomId("LegoWorld", e_exact);
	m_idLegoAnimPresenter = MxAtomId("LegoAnimPresenter", e_exact); // duplicate
	m_idLegoModelPresenter = MxAtomId("LegoModelPresenter", e_exact);
	m_idLegoTexturePresenter = MxAtomId("LegoTexturePresenter", e_exact);
	m_idLegoPhonemePresenter = MxAtomId("LegoPhonemePresenter", e_exact);
	m_idLegoFlcTexturePresenter = MxAtomId("LegoFlcTexturePresenter", e_exact);
	m_idLegoPalettePresenter = MxAtomId("LegoPalettePresenter", e_exact);
	m_idLegoPathPresenter = MxAtomId("LegoPathPresenter", e_exact);
	m_idLegoAnimPresenter = MxAtomId("LegoAnimPresenter", e_exact);
	m_idLegoLoopingAnimPresenter = MxAtomId("LegoLoopingAnimPresenter", e_exact);
	m_idLegoLocomotionAnimPresenter = MxAtomId("LegoLocomotionAnimPresenter", e_exact);
	m_idLegoHideAnimPresenter = MxAtomId("LegoHideAnimPresenter", e_exact);
	m_idLegoPartPresenter = MxAtomId("LegoPartPresenter", e_exact);
	m_idLegoCarBuildAnimPresenter = MxAtomId("LegoCarBuildAnimPresenter", e_exact);
	m_idLegoActionControlPresenter = MxAtomId("LegoActionControlPresenter", e_exact);
	m_idLegoMeterPresenter = MxAtomId("LegoMeterPresenter", e_exact);
	m_idLegoLoadCacheSoundPresenter = MxAtomId("LegoLoadCacheSoundPresenter", e_exact);
	m_idLego3DWavePresenter = MxAtomId("Lego3DWavePresenter", e_exact);
	m_idLegoActor = MxAtomId("LegoActor", e_exact);
	m_idLegoPathActor = MxAtomId("LegoPathActor", e_exact);
	m_idLegoRaceCar = MxAtomId("LegoRaceCar", e_exact);
	m_idLegoJetski = MxAtomId("LegoJetski", e_exact);
	m_idJetskiRace = MxAtomId("JetskiRace", e_exact);
	m_idLegoEntity = MxAtomId("LegoEntity", e_exact);
	m_idLegoCarRaceActor = MxAtomId("LegoCarRaceActor", e_exact);
	m_idLegoJetskiRaceActor = MxAtomId("LegoJetskiRaceActor", e_exact);
	m_idLegoCarBuild = MxAtomId("LegoCarBuild", e_exact);
	m_idInfocenter = MxAtomId("Infocenter", e_exact);
	m_idLegoAnimActor = MxAtomId("LegoAnimActor", e_exact);
	m_idMxControlPresenter = MxAtomId("MxControlPresenter", e_exact);
	m_idRegistrationBook = MxAtomId("RegistrationBook", e_exact);
	m_idHistoryBook = MxAtomId("HistoryBook", e_exact);
	m_idElevatorBottom = MxAtomId("ElevatorBottom", e_exact);
	m_idInfocenterDoor = MxAtomId("InfocenterDoor", e_exact);
	m_idScore = MxAtomId("Score", e_exact);
	m_idScoreState = MxAtomId("ScoreState", e_exact);
	m_idHospital = MxAtomId("Hospital", e_exact);
	m_idIsle = MxAtomId("Isle", e_exact);
	m_idPolice = MxAtomId("Police", e_exact);
	m_idGasStation = MxAtomId("GasStation", e_exact);
	m_idLegoAct2 = MxAtomId("LegoAct2", e_exact);
	m_idLegoAct2State = MxAtomId("LegoAct2State", e_exact);
	m_idCarRace = MxAtomId("CarRace", e_exact);
	m_idLegoRaceCarBuildState = MxAtomId("LegoRaceCarBuildState", e_exact);
	m_idLegoCopterBuildState = MxAtomId("LegoCopterBuildState", e_exact);
	m_idLegoDuneCarBuildState = MxAtomId("LegoDuneCarBuildState", e_exact);
	m_idLegoJetskiBuildState = MxAtomId("LegoJetskiBuildState", e_exact);
	m_idHospitalState = MxAtomId("HospitalState", e_exact);
	m_idInfocenterState = MxAtomId("InfocenterState", e_exact);
	m_idPoliceState = MxAtomId("PoliceState", e_exact);
	m_idGasStationState = MxAtomId("GasStationState", e_exact);
	m_idSkateBoard = MxAtomId("SkateBoard", e_exact);
	m_idHelicopter = MxAtomId("Helicopter", e_exact);
	m_idHelicopterState = MxAtomId("HelicopterState", e_exact);
	m_idDuneBuggy = MxAtomId("DuneBuggy", e_exact);
	m_idPizza = MxAtomId("Pizza", e_exact);
	m_idPizzaMissionState = MxAtomId("PizzaMissionState", e_exact);
	m_idAct2Actor = MxAtomId("Act2Actor", e_exact);
	m_idAct2Brick = MxAtomId("Act2Brick", e_exact);
	m_idAct2GenActor = MxAtomId("Act2GenActor", e_exact);
	m_idAct2PoliceStation = MxAtomId("Act2PoliceStation", e_exact);
	m_idAct3 = MxAtomId("Act3", e_exact);
	m_idAct3State = MxAtomId("Act3State", e_exact);
	m_idDoors = MxAtomId("Doors", e_exact);
	m_idLegoAnimMMPresenter = MxAtomId("LegoAnimMMPresenter", e_exact);
	m_idRaceCar = MxAtomId("RaceCar", e_exact);
	m_idJetski = MxAtomId("Jetski", e_exact);
	m_idBike = MxAtomId("Bike", e_exact);
	m_idMotocycle = MxAtomId("Motocycle", e_exact);
	m_idAmbulance = MxAtomId("Ambulance", e_exact);
	m_idAmbulanceMissionState = MxAtomId("AmbulanceMissionState", e_exact);
	m_idTowTrack = MxAtomId("TowTrack", e_exact);
	m_idTowTrackMissionState = MxAtomId("TowTrackMissionState", e_exact);
	m_idAct3Cop = MxAtomId("Act3Cop", e_exact);
	m_idAct3Brickster = MxAtomId("Act3Brickster", e_exact);
	m_idAct3Shark = MxAtomId("Act3Shark", e_exact);
	m_idBumpBouy = MxAtomId("BumpBouy", e_exact);
	m_idAct3Actor = MxAtomId("Act3Actor", e_exact);
	m_idJetskiRaceState = MxAtomId("JetskiRaceState", e_exact);
	m_idCarRaceState = MxAtomId("CarRaceState", e_exact);
	m_idAct1State = MxAtomId("Act1State", e_exact);
	m_idPizzeria = MxAtomId("Pizzeria", e_exact);
	m_idPizzeriaState = MxAtomId("PizzeriaState", e_exact);
	m_idInfoCenterEntity = MxAtomId("InfoCenterEntity", e_exact);
	m_idHospitalEntity = MxAtomId("HospitalEntity", e_exact);
	m_idGasStationEntity = MxAtomId("GasStationEntity", e_exact);
	m_idPoliceEntity = MxAtomId("PoliceEntity", e_exact);
	m_idBeachHouseEntity = MxAtomId("BeachHouseEntity", e_exact);
	m_idRaceStandsEntity = MxAtomId("RaceStandsEntity", e_exact);
	m_idJukeBoxEntity = MxAtomId("JukeBoxEntity", e_exact);
	m_idRadioState = MxAtomId("RadioState", e_exact);
	m_idCaveEntity = MxAtomId("CaveEntity", e_exact);
	m_idJailEntity = MxAtomId("JailEntity", e_exact);
	m_idMxCompositeMediaPresenter = MxAtomId("MxCompositeMediaPresenter", e_exact);
	m_idJukeBox = MxAtomId("JukeBox", e_exact);
	m_idJukeBoxState = MxAtomId("JukeBoxState", e_exact);
	m_idRaceSkel = MxAtomId("RaceSkel", e_exact);
	m_idAnimState = MxAtomId("AnimState", e_exact);
}

// ==== linker-seeding declarations (mirror real signatures; codegen-inert) ====
class MxStreamChunk;
class MxDSAction;
class MxNotificationParam;
struct MxSmk {
	static void Destroy(MxSmk* p_mxSmk);
};
struct MXIOINFO {
	~MXIOINFO();
};
class MxDSFile {
public:
	virtual unsigned long GetStreamBuffersNum();
};
class MxSmkPresenter {
public:
	virtual void LoadHeader(MxStreamChunk* p_chunk);
};
class MxLoopingFlcPresenter {
public:
	virtual void NextFrame();
};
class MxLoopingSmkPresenter {
public:
	virtual void NextFrame();
};
extern const char* g_parseExtraTokens;
unsigned char KeyValueStringParse(char*, const char*, const char*);
unsigned int ReadData(unsigned char*, unsigned int);
class MxVariableTable {
public:
	void SetVariable(const char*, const char*);
};
class MxDSSubscriber {
public:
	void FreeDataChunk(MxStreamChunk*);
};
class MxPresentationManager {
public:
	virtual void StopPresenters();
};
class MxTickleThread {
public:
	virtual long Run();
};
class MxAudioManager {
public:
	virtual long Create();
};
class MxAutoLock {
public:
	~MxAutoLock();
};
class MxStreamer {
public:
	long Close(const char*);
};
class MxDisplaySurface {
public:
	void ClearScreen();
};
class MxTickleManager {
public:
	virtual int GetClientTickleInterval(MxCore*);
};
class MxVideoManager {
public:
	void SortPresenterList();
};
class MxVideoParamFlags {
public:
	MxVideoParamFlags();
};
class MxVideoParam {
public:
	~MxVideoParam();
};
class MxPalette {
public:
	MxPalette();
};
class MxThread {
public:
	void Terminate();
};
class MxEventManager {
public:
	MxEventManager();
};
class MxMusicManager {
public:
	MxMusicManager();
};
class MxStreamController {
public:
	MxPresenter* FUN_100c1e70(MxDSAction&);
};
class MxMusicPresenter {
public:
	virtual long AddToManager();
};
class MxMIDIPresenter {
public:
	virtual void SetVolume(int);
};
class MxLoopingMIDIPresenter {
public:
	virtual long PutData();
};
class MxEventPresenter {
public:
	MxEventPresenter();
};
class MxRegionCursor {
public:
	virtual ~MxRegionCursor();
};
class MxRAMStreamController {
public:
	virtual long VTable0x24(MxDSAction*);
};
class MxDSBuffer {
public:
	virtual ~MxDSBuffer();
};
class MxDiskStreamController {
public:
	MxDiskStreamController();
};
class MxSemaphore {
public:
	MxSemaphore();
};
class MxDSObjectAction {
public:
	MxDSObjectAction();
};
class MxDSMediaAction {
public:
	virtual ~MxDSMediaAction();
};
class MxDSAnim {
public:
	MxDSAnim();
};
class MxDSSound {
public:
	MxDSSound();
};
class MxDSEvent {
public:
	MxDSEvent();
};
class MxDSStill {
public:
	MxDSStill();
};
class MxDSSerialAction {
public:
	MxDSSerialAction();
};
class MxDSParallelAction {
public:
	MxDSParallelAction();
};
class MxDSSelectAction {
public:
	MxDSSelectAction();
};
class MxDSStreamingAction {
public:
	virtual ~MxDSStreamingAction();
};
class MxRamStreamProvider0;
class MxDiskStreamProvider {
public:
	MxDiskStreamProvider();
};
class MxStartActionNotificationParam {
public:
	virtual MxNotificationParam* Clone() const;
};

void SeedOrder()
{
	new MxDiskStreamProvider;
	ReadData(0, 0);
	((MxDSStreamingAction*) 0)->MxDSStreamingAction::~MxDSStreamingAction();
	((MXIOINFO*) 0)->MXIOINFO::~MXIOINFO();
	((MxDSFile*) 0)->MxDSFile::GetStreamBuffersNum();
	new MxDSSelectAction;
	new MxDSParallelAction;
	new MxDSSerialAction;
	new MxDSMultiAction;
	new MxDSStill;
	new MxDSEvent;
	new MxDSSound;
	new MxDSAnim;
	((MxDSMediaAction*) 0)->MxDSMediaAction::~MxDSMediaAction();
	new MxDSObjectAction;
	new MxSemaphore;
	new MxDiskStreamController;
	((MxDSBuffer*) 0)->MxDSBuffer::~MxDSBuffer();
	((MxRAMStreamController*) 0)->MxRAMStreamController::VTable0x24((MxDSAction*) 0);
	MxSmk::Destroy((MxSmk*) 0);
	((MxRegionCursor*) 0)->MxRegionCursor::~MxRegionCursor();
	((MxStreamChunk*) 0)->MxStreamChunk::~MxStreamChunk();
	new MxEventPresenter;
	((MxLoopingMIDIPresenter*) 0)->MxLoopingMIDIPresenter::PutData();
	((MxMIDIPresenter*) 0)->MxMIDIPresenter::SetVolume(0);
	((MxMusicPresenter*) 0)->MxMusicPresenter::AddToManager();
	((MxStreamController*) 0)->MxStreamController::FUN_100c1e70(*(MxDSAction*) 0);
	new MxMusicManager;
	new MxEventManager;
	((MxDSObject*) 0)->MxDSObject::SetObjectName((const char*) 0);
	((MxThread*) 0)->MxThread::Terminate();
	new MxPalette;
	((MxVideoParam*) 0)->MxVideoParam::~MxVideoParam();
	new MxVideoParamFlags;
	((MxVideoManager*) 0)->MxVideoManager::SortPresenterList();
	((MxDSChunk*) 0)->MxDSChunk::~MxDSChunk();
	((MxTickleManager*) 0)->MxTickleManager::GetClientTickleInterval((MxCore*) 0);
	DecodeFLCFrame(0, 0, 0, 0, 0);
	new MxBitmap;
	((MxDisplaySurface*) 0)->MxDisplaySurface::ClearScreen();
	((MxStillPresenter*) 0)->MxStillPresenter::Clone();
	((MxStreamer*) 0)->MxStreamer::Close((const char*) 0);
	((MxAutoLock*) 0)->MxAutoLock::~MxAutoLock();
	((MxAudioManager*) 0)->MxAudioManager::Create();
	((MxTickleThread*) 0)->MxTickleThread::Run();
	((MxPresentationManager*) 0)->MxPresentationManager::StopPresenters();
	((MxDSSubscriber*) 0)->MxDSSubscriber::FreeDataChunk((MxStreamChunk*) 0);
	((MxVariableTable*) 0)->MxVariableTable::SetVariable((const char*) 0, (const char*) 0);
	KeyValueStringParse(0, 0, 0);
	const char* volatile keep = g_parseExtraTokens;
	((MxCriticalSection*) 0)->MxCriticalSection::Enter();
	((MxCompositePresenter*) 0)->MxCompositePresenter::AdvanceSerialAction((MxPresenter*) 0);
	((MxMediaPresenter*) 0)->MxMediaPresenter::RepeatingTickle();
	((MxPresenter*) 0)->MxPresenter::Enable(0);
	((MxLoopingSmkPresenter*) 0)->MxLoopingSmkPresenter::NextFrame();
	((MxLoopingFlcPresenter*) 0)->MxLoopingFlcPresenter::NextFrame();
	((MxSmkPresenter*) 0)->MxSmkPresenter::LoadHeader(0);
	((MxFlcPresenter*) 0)->MxFlcPresenter::LoadHeader(0);
	((MxVideoPresenter*) 0)->MxVideoPresenter::NextFrame();
	((MxWavePresenter*) 0)->MxWavePresenter::Pause();
	((MxSoundPresenter*) 0)->MxSoundPresenter::AddToManager();
}

// FUNCTION: LEGO1 0x10009a90
// FUNCTION: BETA10 0x100a1021
MxCore* LegoObjectFactory::Create(const char* p_name)
{
	MxCore* object = NULL;
	MxAtomId atom(p_name, e_exact);

	if (m_idLegoModelPresenter == atom) {
		object = new LegoModelPresenter();
	}
	else if (m_idLegoTexturePresenter == atom) {
		object = new LegoTexturePresenter();
	}
	else if (m_idLegoPhonemePresenter == atom) {
		object = new LegoPhonemePresenter();
	}
	else if (m_idLegoFlcTexturePresenter == atom) {
		object = new LegoFlcTexturePresenter();
	}
	else if (m_idLegoEntityPresenter == atom) {
		object = new LegoEntityPresenter();
	}
	else if (m_idLegoActorPresenter == atom) {
		object = new LegoActorPresenter();
	}
	else if (m_idLegoWorldPresenter == atom) {
		object = new LegoWorldPresenter();
	}
	else if (m_idLegoWorld == atom) {
		object = new LegoWorld();
	}
	else if (m_idLegoPalettePresenter == atom) {
		object = new LegoPalettePresenter();
	}
	else if (m_idLegoPathPresenter == atom) {
		object = new LegoPathPresenter();
	}
	else if (m_idLegoAnimPresenter == atom) {
		object = new LegoAnimPresenter();
	}
	else if (m_idLegoLoopingAnimPresenter == atom) {
		object = new LegoLoopingAnimPresenter();
	}
	else if (m_idLegoLocomotionAnimPresenter == atom) {
		object = new LegoLocomotionAnimPresenter();
	}
	else if (m_idLegoHideAnimPresenter == atom) {
		object = new LegoHideAnimPresenter();
	}
	else if (m_idLegoPartPresenter == atom) {
		object = new LegoPartPresenter();
	}
	else if (m_idLegoCarBuildAnimPresenter == atom) {
		object = new LegoCarBuildAnimPresenter();
	}
	else if (m_idLegoActionControlPresenter == atom) {
		object = new LegoActionControlPresenter();
	}
	else if (m_idLegoMeterPresenter == atom) {
		object = new LegoMeterPresenter();
	}
	else if (m_idLegoLoadCacheSoundPresenter == atom) {
		object = new LegoLoadCacheSoundPresenter();
	}
	else if (m_idLego3DWavePresenter == atom) {
		object = new Lego3DWavePresenter();
	}
	else if (m_idLegoActor == atom) {
		object = new LegoActor();
	}
	else if (m_idLegoPathActor == atom) {
		object = new LegoPathActor();
	}
	else if (m_idJetskiRace == atom) {
		object = new JetskiRace();
	}
	else if (m_idLegoEntity == atom) {
		object = new LegoEntity();
	}
	else if (m_idLegoRaceCar == atom) {
		object = new LegoRaceCar();
	}
	else if (m_idLegoJetski == atom) {
		object = new LegoJetski();
	}
	else if (m_idLegoCarRaceActor == atom) {
		object = new LegoCarRaceActor();
	}
	else if (m_idLegoJetskiRaceActor == atom) {
		object = new LegoJetskiRaceActor();
	}
	else if (m_idLegoCarBuild == atom) {
		object = new LegoCarBuild();
	}
	else if (m_idInfocenter == atom) {
		object = new Infocenter();
	}
	else if (m_idLegoAnimActor == atom) {
		object = new LegoAnimActor();
	}
	else if (m_idMxControlPresenter == atom) {
		object = new MxControlPresenter();
	}
	else if (m_idRegistrationBook == atom) {
		object = new RegistrationBook();
	}
	else if (m_idHistoryBook == atom) {
		object = new HistoryBook();
	}
	else if (m_idElevatorBottom == atom) {
		object = new ElevatorBottom();
	}
	else if (m_idInfocenterDoor == atom) {
		object = new InfocenterDoor();
	}
	else if (m_idScore == atom) {
		object = new Score();
	}
	else if (m_idScoreState == atom) {
		object = new ScoreState();
	}
	else if (m_idHospital == atom) {
		object = new Hospital();
	}
	else if (m_idIsle == atom) {
		object = new Isle();
	}
	else if (m_idPolice == atom) {
		object = new Police();
	}
	else if (m_idGasStation == atom) {
		object = new GasStation();
	}
	else if (m_idLegoAct2 == atom) {
		object = new LegoAct2();
	}
	else if (m_idLegoAct2State == atom) {
		object = new LegoAct2State();
	}
	else if (m_idCarRace == atom) {
		object = new CarRace();
	}
	else if (m_idLegoRaceCarBuildState == atom || m_idLegoCopterBuildState == atom || m_idLegoDuneCarBuildState == atom || m_idLegoJetskiBuildState == atom) {
		object = new LegoVehicleBuildState(p_name);
	}
	else if (m_idHospitalState == atom) {
		object = new HospitalState();
	}
	else if (m_idInfocenterState == atom) {
		object = new InfocenterState();
	}
	else if (m_idPoliceState == atom) {
		object = new PoliceState();
	}

	if (object != NULL) {
		return object;
	}

	if (m_idGasStationState == atom) {
		object = new GasStationState();
	}
	else if (m_idSkateBoard == atom) {
		object = new SkateBoard();
	}
	else if (m_idHelicopter == atom) {
		object = new Helicopter();
	}
	else if (m_idHelicopterState == atom) {
		object = new HelicopterState();
	}
	else if (m_idDuneBuggy == atom) {
		object = new DuneBuggy();
	}
	else if (m_idPizza == atom) {
		object = new Pizza();
	}
	else if (m_idPizzaMissionState == atom) {
		object = new PizzaMissionState();
	}
	else if (m_idAct2Actor == atom) {
		Act2Actor* actor = new Act2Actor();
		((LegoAct2*) CurrentWorld())->SetAmbulanceActor(actor);
		object = actor;
	}
	else if (m_idAct2Brick == atom) {
		object = new Act2Brick();
	}
	else if (m_idAct2GenActor == atom) {
		object = new Act2GenActor();
	}
	else if (m_idAct2PoliceStation == atom) {
		object = new Act2PoliceStation();
	}
	else if (m_idAct3 == atom) {
		object = new Act3();
	}
	else if (m_idAct3State == atom) {
		object = new Act3State();
	}
	else if (m_idDoors == atom) {
		object = new Doors();
	}
	else if (m_idLegoAnimMMPresenter == atom) {
		object = new LegoAnimMMPresenter();
	}
	else if (m_idRaceCar == atom) {
		object = new RaceCar();
	}
	else if (m_idJetski == atom) {
		object = new Jetski();
	}
	else if (m_idBike == atom) {
		object = new Bike();
	}
	else if (m_idMotocycle == atom) {
		object = new Motocycle();
	}
	else if (m_idAmbulance == atom) {
		object = new Ambulance();
	}
	else if (m_idAmbulanceMissionState == atom) {
		object = new AmbulanceMissionState();
	}
	else if (m_idTowTrack == atom) {
		object = new TowTrack();
	}
	else if (m_idTowTrackMissionState == atom) {
		object = new TowTrackMissionState();
	}
	else if (m_idAct3Cop == atom) {
		object = new Act3Cop();
	}
	else if (m_idAct3Brickster == atom) {
		object = new Act3Brickster();
	}
	else if (m_idAct3Shark == atom) {
		object = new Act3Shark();
	}
	else if (m_idAct3Actor == atom) {
		object = new Act3Actor();
	}
	else if (m_idBumpBouy == atom) {
		object = new BumpBouy();
	}
	else if (m_idJetskiRaceState == atom) {
		object = new JetskiRaceState();
	}
	else if (m_idCarRaceState == atom) {
		object = new CarRaceState();
	}
	else if (m_idAct1State == atom) {
		object = new Act1State();
	}
	else if (m_idPizzeria == atom) {
		object = new Pizzeria();
	}
	else if (m_idPizzeriaState == atom) {
		object = new PizzeriaState();
	}
	else if (m_idInfoCenterEntity == atom) {
		object = new InfoCenterEntity();
	}
	else if (m_idHospitalEntity == atom) {
		object = new HospitalEntity();
	}
	else if (m_idGasStationEntity == atom) {
		object = new GasStationEntity();
	}
	else if (m_idPoliceEntity == atom) {
		object = new PoliceEntity();
	}
	else if (m_idBeachHouseEntity == atom) {
		object = new BeachHouseEntity();
	}
	else if (m_idJukeBoxEntity == atom) {
		object = new JukeBoxEntity();
	}
	else if (m_idRaceStandsEntity == atom) {
		object = new RaceStandsEntity();
	}
	else if (m_idRadioState == atom) {
		object = new RadioState();
	}
	else if (m_idCaveEntity == atom) {
		object = new CaveEntity();
	}
	else if (m_idJailEntity == atom) {
		object = new JailEntity();
	}
	else if (m_idMxCompositeMediaPresenter == atom) {
		object = new MxCompositeMediaPresenter();
	}
	else if (m_idJukeBox == atom) {
		object = new JukeBox();
	}
	else if (m_idJukeBoxState == atom) {
		object = new JukeBoxState();
	}
	else if (m_idRaceSkel == atom) {
		object = new RaceSkel();
	}
	else if (m_idAnimState == atom) {
		object = new AnimState();
	}
	else {
		object = MxObjectFactory::Create(p_name);
	}

	// clang-format off
	assert(object!=NULL);
	// clang-format on

	return object;
}

// FUNCTION: LEGO1 0x1000fb30
void LegoObjectFactory::Destroy(MxCore* p_object)
{
	delete p_object;
}

// Declaration-record carrier (dial campaign): end-of-file sink for
// this translation unit's declaration state.  Neutral stand-in.
class MxUnkRecordSW7000;
class MxUnkRecordSW7001;
class MxUnkRecordSW7002;
class MxUnkRecordSW7003;
class MxUnkRecordSW7004;
class MxUnkRecordSW7005;
class MxUnkRecordSW7006;
class MxUnkRecordSW7007;
class MxUnkRecordSW7008;
class MxUnkRecordSW7009;
class MxUnkRecordSW7010;
class MxUnkRecordSW7011;
class MxUnkRecordSW7012;
class MxUnkRecordSW7013;
class MxUnkRecordSW7014;
class MxUnkRecordSW7015;
class MxUnkRecordSW7016;
class MxUnkRecordSW7017;
class MxUnkRecordSW7018;
class MxUnkRecordSW7019;
class MxUnkRecordSW7020;
class MxUnkRecordSW7021;
class MxUnkRecordSW7022;
class MxUnkRecordSW7023;
class MxUnkRecordSW7024;
class MxUnkRecordSW7025;
class MxUnkRecordSW7026;
class MxUnkRecordSW7027;
class MxUnkRecordSW7028;
class MxUnkRecordSW7029;
class MxUnkRecordSW7030;
class MxUnkRecordSW7031;
class MxUnkRecordSW7032;
class MxUnkRecordSW7033;
class MxUnkRecordSW7034;
class MxUnkRecordSW7035;
class MxUnkRecordSW7036;
class MxUnkRecordSW7037;
class MxUnkRecordSW7038;
class MxUnkRecordSW7039;
class MxUnkRecordSW7040;
class MxUnkRecordSW7041;
class MxUnkRecordSW7042;
class MxUnkRecordSW7043;
class MxUnkRecordSW7044;
class MxUnkRecordSW7045;
class MxUnkRecordSW7046;
class MxUnkRecordSW7047;
class MxUnkRecordSW7048;
class MxUnkRecordSW7049;
class MxUnkRecordSW7050;
class MxUnkRecordSW7051;
class MxUnkRecordSW7052;
class MxUnkRecordSW7053;
class MxUnkRecordSW7054;
class MxUnkRecordSW7055;
class MxUnkRecordSW7056;
class MxUnkRecordSW7057;
class MxUnkRecordSW7058;
class MxUnkRecordSW7059;
class MxUnkRecordSW7060;
class MxUnkRecordSW7061;
class MxUnkRecordSW7062;
class MxUnkRecordSW7063;
class MxUnkRecordSW7064;
class MxUnkRecordSW7065;
class MxUnkRecordSW7066;
class MxUnkRecordSW7067;
class MxUnkRecordSW7068;
class MxUnkRecordSW7069;
class MxUnkRecordSW7070;
class MxUnkRecordSW7071;
class MxUnkRecordSW7072;
class MxUnkRecordSW7073;
class MxUnkRecordSW7074;
class MxUnkRecordSW7075;
class MxUnkRecordSW7076;
class MxUnkRecordSW7077;
class MxUnkRecordSW7078;
class MxUnkRecordSW7079;
class MxUnkRecordSW7080;
class MxUnkRecordSW7081;
class MxUnkRecordSW7082;
class MxUnkRecordSW7083;
class MxUnkRecordSW7084;
class MxUnkRecordSW7085;
class MxUnkRecordSW7086;
class MxUnkRecordSW7087;
class MxUnkRecordSW7088;
class MxUnkRecordSW7089;
class MxUnkRecordSW7090;
class MxUnkRecordSW7091;
class MxUnkRecordSW7092;
class MxUnkRecordSW7093;
class MxUnkRecordSW7094;
class MxUnkRecordSW7095;
class MxUnkRecordSW7096;
class MxUnkRecordSW7097;
class MxUnkRecordSW7098;
class MxUnkRecordSW7099;
class MxUnkRecordSW7100;
class MxUnkRecordSW7101;
class MxUnkRecordSW7102;
class MxUnkRecordSW7103;
class MxUnkRecordSW7104;
class MxUnkRecordSW7105;
class MxUnkRecordSW7106;
class MxUnkRecordSW7107;
class MxUnkRecordSW7108;
class MxUnkRecordSW7109;
