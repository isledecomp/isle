#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "actionsfwd.h"
#include "decomp.h"
#include "legobackgroundcolor.h"
#include "legofullscreenmovie.h"
#include "misc/legostorage.h"
#include "mxtypes.h"
#include "mxvariabletable.h"

class LegoState;
class MxVariable;
class MxString;

// SIZE 0x08
struct ColorStringStruct {
	const char* m_targetName;
	const char* m_colorName;
};

// SIZE 0x430
class LegoGameState {
public:
	enum Act {
		e_actNotFound = -1,
		e_act1,
		e_act2,
		e_act3
	};

	enum Area {
		e_undefined = 0,
		e_previousArea = 0,
		e_isle,
		e_infomain,
		e_infodoor,
		e_unk4,
		e_elevbott,
		e_elevride,
		e_elevride2,
		e_elevopen,
		e_seaview,
		e_observe,
		e_elevdown,
		e_regbook,
		e_infoscor,
		e_jetrace,
		e_jetrace2,
		e_jetraceExterior,
		e_unk17,
		e_carrace,
		e_carraceExterior,
		e_unk20,
		e_unk21,
		e_pizzeriaExterior,

		e_garageExterior = 25,
		e_garage,
		e_garadoor,
		e_unk28,
		e_hospitalExterior,
		e_hospital,
		e_unk31,
		e_policeExterior,
		e_unk33,
		e_police,
		e_polidoor,
		e_copterbuild,
		e_dunecarbuild,
		e_jetskibuild,
		e_racecarbuild,
		e_unk40,
		e_unk41,
		e_unk42,

		e_unk45 = 45,
		e_act2main,
		e_act3script,
		e_unk48,
		e_unk49,

		e_jukeboxw = 53,
		e_unk54,
		e_unk55,
		e_histbook,
		e_bike,
		e_dunecar,
		e_motocycle,
		e_copter,
		e_skateboard,
		e_ambulance,
		e_towtrack,
		e_jetski,

		e_unk66 = 66
	};

	// SIZE 0x0e
	struct Username {
		Username();
		inline Username(Username& p_other) { Set(p_other); }
		inline void Set(Username& p_other) { memcpy(m_letters, p_other.m_letters, sizeof(m_letters)); }

		MxResult ReadWrite(LegoStorage* p_storage);
		Username& operator=(const Username& p_other);

		MxS16 m_letters[7]; // 0x00
	};

	// SIZE 0x2c
	struct ScoreItem {
		undefined2 m_unk0x00; // 0x00
		MxU8 m_state[5][5];   // 0x02
		Username m_name;      // 0x1c
		undefined2 m_unk0x2a; // 0x2a
	};

	// SIZE 0x372
	struct History {
		History();
		void WriteScoreHistory();
		void FUN_1003ccf0(LegoFile&);

		inline ScoreItem* GetScore(MxS16 p_index) { return p_index >= m_count ? NULL : &m_scores[p_index]; }

		MxS16 m_count;          // 0x00
		ScoreItem m_scores[20]; // 0x02
		undefined2 m_unk0x372;  // 0x372
	};

	LegoGameState();
	~LegoGameState();

	void SetActor(MxU8 p_actorId);
	void RemoveActor();
	void ResetROI();

	MxResult Save(MxULong);
	MxResult DeleteState();
	MxResult Load(MxULong);

	void SerializePlayersInfo(MxS16 p_flags);
	MxResult AddPlayer(Username& p_player);
	void SwitchPlayer(MxS16 p_playerId);
	MxS16 FindPlayer(Username& p_player);

	void SerializeScoreHistory(MxS16 p_flags);
	void SetSavePath(char*);

	LegoState* GetState(const char* p_stateName);
	LegoState* CreateState(const char* p_stateName);

	void GetFileSavePath(MxString* p_outPath, MxU8 p_slotn);
	void StopArea(Area p_area);
	void SwitchArea(Area p_area);
	void Init();

	inline MxU8 GetActorId() { return m_actorId; }
	inline Act GetCurrentAct() { return m_currentAct; }
	inline Act GetLoadedAct() { return m_loadedAct; }
	inline Area GetCurrentArea() { return m_currentArea; }
	inline Area GetPreviousArea() { return m_previousArea; }
	inline JukeboxScript::Script GetUnknown0x41c() { return m_unk0x41c; }
	inline Area GetUnknown0x42c() { return m_unk0x42c; }
	inline History* GetHistory() { return &m_history; }

	inline void SetDirty(MxBool p_dirty) { m_isDirty = p_dirty; }
	inline void SetCurrentArea(Area p_currentArea) { m_currentArea = p_currentArea; }
	inline void SetPreviousArea(Area p_previousArea) { m_previousArea = p_previousArea; }
	inline void SetActorId(MxU8 p_actorId) { m_actorId = p_actorId; }
	inline void SetUnknown0x41c(JukeboxScript::Script p_unk0x41c) { m_unk0x41c = p_unk0x41c; }
	inline void SetUnknown0x42c(Area p_unk0x42c) { m_unk0x42c = p_unk0x42c; }
	inline Username* GetPlayersIndex(MxS32 p_index) { return &m_players[p_index]; }
	inline MxS16 GetPlayerCount() { return m_playerCount; }
	inline LegoBackgroundColor* GetBackgroundColor() { return m_backgroundColor; }

	void SetCurrentAct(Act p_currentAct);
	void FindLoadedAct();

private:
	void RegisterState(LegoState* p_state);
	MxResult WriteVariable(LegoStorage* p_storage, MxVariableTable* p_from, const char* p_variableName);
	MxResult WriteEndOfVariables(LegoStorage* p_storage);
	MxS32 ReadVariable(LegoStorage* p_storage, MxVariableTable* p_to);
	void SetColors();
	void SetROIHandlerFunction();

	char* m_savePath;                           // 0x00
	MxS16 m_stateCount;                         // 0x04
	LegoState** m_stateArray;                   // 0x08
	MxU8 m_actorId;                             // 0x0c
	Act m_currentAct;                           // 0x10
	Act m_loadedAct;                            // 0x14
	LegoBackgroundColor* m_backgroundColor;     // 0x18
	LegoBackgroundColor* m_tempBackgroundColor; // 0x1c
	LegoFullScreenMovie* m_fullScreenMovie;     // 0x20
	MxU16 m_unk0x24;                            // 0x24

	// Member visibility needs to be refactored, since most members are accessed directly.

public:
	MxS16 m_playerCount;   // 0x26
	Username m_players[9]; // 0x28

private:
	History m_history;                // 0xa6
	undefined2 m_unk0x41a;            // 0x41a
	JukeboxScript::Script m_unk0x41c; // 0x41c
	MxBool m_isDirty;                 // 0x420

public:
	Area m_currentArea;  // 0x424
	Area m_previousArea; // 0x428

private:
	Area m_unk0x42c; // 0x42c
};

MxBool ROIHandlerFunction(const char* p_input, char* p_output, MxU32 p_copyLen);

// SYNTHETIC: LEGO1 0x1003c860
// LegoGameState::ScoreItem::ScoreItem

#endif // LEGOGAMESTATE_H
