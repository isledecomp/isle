#ifndef RADIO_H
#define RADIO_H

#include "mxcore.h"

// VTABLEADDR 0x100d6d10
class Radio : public MxCore {
public:
	virtual ~Radio() override;
};

#endif // RADIO_H
