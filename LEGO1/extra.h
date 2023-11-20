#ifndef EXTRA_H
#define EXTRA_H

// Items related to the Extra string of key-value pairs found in MxOb

enum ExtraActionType {
	ExtraActionType_none = 0,
	ExtraActionType_opendisk = 1,
	ExtraActionType_openram = 2,
	ExtraActionType_close = 3,
	ExtraActionType_start = 4,
	ExtraActionType_stop = 5,
	ExtraActionType_run = 6,
	ExtraActionType_exit = 7,
	ExtraActionType_enable = 8,
	ExtraActionType_disable = 9,
	ExtraActionType_notify = 10,
	ExtraActionType_unknown = 11,
};

#endif // EXTRA_H
