#ifndef SMK_H
#define SMK_H

struct SmackSum {
	unsigned long m_totalTime;
	unsigned long m_ms100PerFrame;
	unsigned long m_totalOpenTime;
	unsigned long m_totalFrames;
	unsigned long m_skippedFrames;
	unsigned long m_totalBlitTime;
	unsigned long m_totalReadTime;
	unsigned long m_totalDecompressTime;
	unsigned long m_totalBackReadTime;
	unsigned long m_totalReadSpeed;
	unsigned long m_slowestFrameTime;
	unsigned long m_slowestTwoFrameTime;
	unsigned long m_slowestFrameNum;
	unsigned long m_slowestTwoFrameNum;
	unsigned long m_averageFrameSize;
	unsigned long m_highestOneSecRate;
	unsigned long m_highestOneSecFrame;
	unsigned long m_highestMemAmount;
	unsigned long m_totalExtraMemory;
	unsigned long m_highestExtraUsed;
};

// SIZE 0x390
struct Smack {
	struct Header {
		unsigned long m_version;           // 0x00
		unsigned long m_width;             // 0x04
		unsigned long m_height;            // 0x08
		unsigned long m_frames;            // 0x0c
		unsigned long m_msInAFrame;        // 0x10
		unsigned long m_smkType;           // 0x14
		unsigned long m_audioTrackSize[7]; // 0x18
		unsigned long m_treeSize;          // 0x34
		unsigned long m_codeSize;          // 0x38
		unsigned long m_abSize;            // 0x3c
		unsigned long m_detailSize;        // 0x40
		unsigned long m_typeSize;          // 0x44
		unsigned long m_trackType[7];      // 0x48
		unsigned long m_extra;             // 0x64
	};

	Header m_header;              // 0x00
	unsigned long m_newPalette;   // 0x68
	unsigned char m_palette[772]; // 0x6c
	unsigned long m_frameNum;     // 0x370
	unsigned long m_lastRectX;    // 0x374
	unsigned long m_lastRectY;    // 0x378
	unsigned long m_lastRectW;    // 0x37c
	unsigned long m_lastRectH;    // 0x380
	unsigned long m_openFlags;    // 0x384
	unsigned long m_leftOfs;      // 0x388
	unsigned long m_topOfs;       // 0x38c
};

#endif // SMK_H
