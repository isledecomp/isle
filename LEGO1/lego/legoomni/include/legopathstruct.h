#ifndef LEGOPATHSTRUCT_H
#define LEGOPATHSTRUCT_H

#include "decomp.h"
#include "mxatom.h"
#include "mxnotificationparam.h"
#include "mxtypes.h"

class LegoPathActor;
class LegoWorld;

// VTABLE: LEGO1 0x100d6230
// SIZE 0x10
class LegoPathStructNotificationParam : public MxNotificationParam {
public:
	LegoPathStructNotificationParam(NotificationId p_type, MxCore* p_sender, MxU8 p_trigger, MxS16 p_data)
		: MxNotificationParam()
	{
		m_type = p_type;
		m_sender = p_sender;
		m_data = p_data;
		m_trigger = p_trigger;
	}

	// FUNCTION: LEGO1 0x1001bac0
	MxNotificationParam* Clone() const override
	{
		return new LegoPathStructNotificationParam(m_type, m_sender, m_trigger, m_data);
	} // vtable+0x04

	// FUNCTION: BETA10 0x10024270
	MxU8 GetTrigger() { return m_trigger; }

	// FUNCTION: BETA10 0x100242a0
	MxS16 GetData() { return m_data; }

protected:
	MxS16 m_data;   // 0x0c
	MxU8 m_trigger; // 0x0e
};

// VTABLE: LEGO1 0x100d7d9c
// SIZE 0x0c
struct LegoPathStructBase {
public:
	enum {
		c_bit1 = 0x01 << 24,
		c_bit2 = 0x02 << 24,
		c_bit3 = 0x04 << 24,
		c_bit4 = 0x08 << 24,
		c_bit5 = 0x10 << 24,
		c_bit6 = 0x20 << 24,
		c_bit7 = 0x40 << 24
	};

	LegoPathStructBase() : m_name(NULL), m_flags(0) {}

	// FUNCTION: LEGO1 0x10047420
	virtual ~LegoPathStructBase()
	{
		if (m_name != NULL) {
			delete[] m_name;
		}
	}

	char* m_name;  // 0x04
	MxU32 m_flags; // 0x08
};

// VTABLE: LEGO1 0x100d7da0
// SIZE 0x14
class LegoPathStruct : public LegoPathStructBase {
public:
	enum Trigger {
		c_camAnim = 'C',
		c_d = 'D',
		c_e = 'E',
		c_g = 'G',
		c_h = 'H',
		c_music = 'M',
		c_s = 'S',
		c_w = 'W'
	};

	// FUNCTION: LEGO1 0x100473a0
	LegoPathStruct() : m_world(NULL) {}

	// FUNCTION: LEGO1 0x10047470
	~LegoPathStruct() override {}

	virtual void HandleTrigger(LegoPathActor* p_actor, MxBool p_direction, MxU32 p_data); // vtable+0x04

	void SetWorld(LegoWorld* p_world) { m_world = p_world; }
	void SetAtomId(const MxAtomId& p_atomId) { m_atomId = p_atomId; }

private:
	MxBool HandleTrigger(LegoPathActor* p_actor, MxBool p_direction, MxU32 p_data, MxBool p_invertDirection);
	void HandleAction(const char* p_name, MxU32 p_data, MxBool p_start);
	void PlayMusic(MxBool p_direction, MxU32 p_data);

	LegoWorld* m_world; // 0x0c
	MxAtomId m_atomId;  // 0x10
};

// SYNTHETIC: LEGO1 0x1001bb80
// LegoPathStructNotificationParam::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001bbf0
// LegoPathStructNotificationParam::~LegoPathStructNotificationParam

// SYNTHETIC: LEGO1 0x10047440
// LegoPathStructBase::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10047890
// LegoPathStruct::`vector deleting destructor'

#endif // LEGOPATHSTRUCT_H
