//region File Header Structures

typedef struct _MY_IMAGE_DOS_HEADER
{
	WORD e_magic; // MZ
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew; // IMAGE_NT_HEAERS 구조체의 시작 오프셋 값
};

typedef struct _MY_IMAGE_NT_HEADERS {
	DWORD                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
};

// IMAGE_NT_HEADERS
typedef struct _MY_SIGNATURE {
	DWORD                   Signature; // PE
};

typedef struct _MY_IMAGE_FILE_HEADER
{
	WORD  Machine; // CPU ID를 나타내는 시그니쳐
	WORD  NumberOfSections; // 섹션의 갯수
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader; // IMAGE_OPTIONAL_HEADER 구조체의 크기
	WORD  Characteristics; // 파일의 속성
};

typedef struct _MY_IMAGE_OPTIONAL_HEADER
{
	WORD                 Magic; // IMAGE_OPTIONAL_HEADER를 나타내는 시그니쳐
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint; // EP의 RVA 값
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase; // PE 파일이 로딩되는 시작 주소
	DWORD                SectionAlignment; // 메모리에서의 섹션의 최소단위
	DWORD                FileAlignment; // 파일에서의 섹션의 최소단위
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage; // 가상 메모리에서 PE Image가 차지하는 크기(로딩된 크기)
	DWORD                SizeOfHeaders; // PE 헤더의 전체 크기(FileAlignment의 배수)
	DWORD                CheckSum;
	WORD                 Subsystem; // 서브시스템 종류 정의
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes; // DataDirectory 배열의 갯수
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // IMAGE_DATA_DIRECTORY 구조체의 배열
};

typedef struct _MY_IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

typedef struct _MY_IMAGE_SECTION_HEADER
{
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize; // 메모리에서 섹션이 차지하는 크기
	} Misc;
	DWORD VirtualAddress; // 메모리에서의 섹션의 시작 주소 (RVA)
	DWORD SizeOfRawData; // 파일에서 섹션이 차지하는 크기
	DWORD PointerToRawData; // 파일에서 섹션의 시작 위치
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics; // 섹션의 특징 (bit OR)
};

typedef struct _MY_IMAGE_EXPORT_DIRECTORY
{
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions; // export하는 함수 갯수
	DWORD NumberOfNames;
	DWORD AddressOfFunctions; // export 함수 주소 배열
	DWORD AddressOfNames; // 함수 이름 주소 배열
	DWORD AddressOfNameOrdinals;
};

typedef struct _MY_IMAGE_DATA_DIRECTORY 
{
	DWORD VirtualAddress;
	DWORD Size;
};

typedef struct _MY_IMAGE_IMPORT_DESCRIPTOR
{
	union{
		DWORD Characteristics;
		DWORD OriginalFirstThunk; // INT(Import Name Table) RVA 주소
	};
	DWORD TimeDataStamp;
	DWORD ForwarderChain;
	DWORD Name; // DLL 이름 RVA 주소
	DWORD FirstThunk; // IAT(Import Address Table) RVA 주소
}; 

typedef struct _MY_IMAGE_THUNK_DATA32
{
	union
	{
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal; // 임포트한 함수에 대한 Ordinal 값을 명시할 때 사용
		DWORD AddressOfData; //_IMAGE_IMPORT_BY_NAME 구조체 주소
	};
};

typedef struct _IMAGE_IUMPORT_BY_NAME
{
	WORD Hint;
	CHAR Name[1];
};

typedef struct TMP
{
	WORD  tmp_1;
	WORD  tmp_2;
	WORD  tmp_3;
};