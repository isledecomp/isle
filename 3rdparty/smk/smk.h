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

struct Smack {
	unsigned long m_version;
	unsigned long m_width;
	unsigned long m_height;
	unsigned long m_frames;
	unsigned long m_msInAFrame;
	unsigned long m_smkType;
	unsigned long m_audioTrackSize[7];
	unsigned long m_treeSize;
	unsigned long m_codeSize;
	unsigned long m_abSize;
	unsigned long m_detailSize;
	unsigned long m_typeSize;
	unsigned long m_trackType[7];
	unsigned long m_extra;
	unsigned long m_newPalette;
	unsigned int m_palette[193];
	unsigned long m_frameNum;
	unsigned long m_lastRectX;
	unsigned long m_lastRectY;
	unsigned long m_lastRectW;
	unsigned long m_lastRectH;
	unsigned long m_openFlags;
	unsigned long m_leftOfs;
	unsigned long m_topOfs;
};

#endif // SMK_H
