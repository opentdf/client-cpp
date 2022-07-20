#ifndef VIRTRU_ZIP_HEADERS_H_INCLUDED
#define VIRTRU_ZIP_HEADERS_H_INCLUDED

#include <cstdint>

static constexpr auto ZIP64EXTSIZE = 24; // Zip64 extended information extra field size
static constexpr auto ZIP64_EXTID  = 0x0001; // Extra field Zip64 header ID
static constexpr auto ZIP64_MAGICVAL = 0xFFFFFFFF;

enum class ZipSignatures : uint32_t
{
    EndOfCentralDirectorySignature             = 0x06054b50,
    CentralFileHeaderSignature                 = 0x02014b50,
    LocalFileHeaderSignature                   = 0x04034b50,
    Zip64EndOfCentralDirectoryLocatorSignature = 0x07064B50,
    Zip64EndOfCentralDirectorySignature        = 0x06064B50,
};


#pragma pack(1)
struct EndOfCentralDirectoryRecord
{
    uint32_t signature;
    uint16_t diskNumber;
    uint16_t startDiskNumber;
    uint16_t numberCentralDirectoryRecord;
    uint16_t totalCentralDirectoryRecord;
    uint32_t sizeOfCentralDirectory;
    uint32_t centralDirectoryOffset;
    uint16_t commentLength;
};

struct Zip64EndOfCentralDirectoryRecord
{
    uint32_t signature;
    uint64_t recordSize;
    uint16_t versionMadeBy;
    uint16_t versionToExtract;
    uint32_t diskNumber;
    uint32_t centralDirectoryDiskNumber;
    uint64_t entryCountThisDisk;
    uint64_t totalEntryCount;
    uint64_t centralDirectorySize;
    uint64_t startingDiskCentralDirectoryOffset;
};

struct Zip64EndOfCentralDirectoryRecordLocator
{
    uint32_t signature;
    uint32_t centralDirectoryStartDiskNumber;
    uint64_t centralDirectoryOffset;
    uint32_t numberOfDisks;
};

struct Zip64ExtendedLocalInfoExtraField
{
    uint16_t signature;
    uint16_t size;
    uint64_t originalSize;
    uint64_t compressedSize;
};

struct Zip64ExtendedInfoExtraField
{
    uint16_t signature;
    uint16_t size;
    uint64_t originalSize;
    uint64_t compressedSize;
    uint64_t localFileHeaderOffset;
};

struct LocalFileHeader
{
    uint32_t signature;
    uint16_t version;
    uint16_t flags;
    uint16_t compressionMethod;
    uint16_t lastModifiedTime;
    uint16_t lastModifiedDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldLength;
};

struct CentralDirectoryFileHeader
{
    uint32_t signature;
    uint16_t versionCreated;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compressionMethod;
    uint16_t lastModifiedTime;
    uint16_t lastModifiedDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldLength;
    uint16_t fileCommentLength;
    uint16_t diskNumberStart;
    uint16_t internalFileAttributes;
    uint32_t externalFileAttributes;
    uint32_t localHeaderOffset;
};
#pragma pack()

#endif   // VIRTRU_ZIP_HEADERS_H_INCLUDED