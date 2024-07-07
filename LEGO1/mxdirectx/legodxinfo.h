#ifndef LEGODXINFO_H
#define LEGODXINFO_H

#include "mxdirectxinfo.h"

// VTABLE: CONFIG 0x4060e4
// VTABLE: LEGO1 0x100d9cc8
// VTABLE: BETA10 0x101befb4
// SIZE 0x14
class LegoDeviceEnumerate : public MxDeviceEnumerate {
public:
	int ProcessDeviceBytes(int p_deviceNum, GUID& p_guid);
	int ParseDeviceName(const char* p_deviceId);
	int FormatDeviceName(char* p_buffer, const MxDriver* p_ddInfo, const Direct3DDeviceInfo* p_d3dInfo) const;

	// SYNTHETIC: BETA10 0x100d8d10
	// LegoDeviceEnumerate::LegoDeviceEnumerate

	// SYNTHETIC: LEGO1 0x1007b590
	// SYNTHETIC: BETA10 0x100d8da0
	// LegoDeviceEnumerate::~LegoDeviceEnumerate
};

#endif // LEGODXINFO_H
