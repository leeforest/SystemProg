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
	LONG e_lfanew; // IMAGE_NT_HEAERS ����ü�� ���� ������ ��
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
	WORD  Machine; // CPU ID�� ��Ÿ���� �ñ״���
	WORD  NumberOfSections; // ������ ����
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader; // IMAGE_OPTIONAL_HEADER ����ü�� ũ��
	WORD  Characteristics; // ������ �Ӽ�
};

typedef struct _MY_IMAGE_OPTIONAL_HEADER
{
	WORD                 Magic; // IMAGE_OPTIONAL_HEADER�� ��Ÿ���� �ñ״���
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint; // EP�� RVA ��
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase; // PE ������ �ε��Ǵ� ���� �ּ�
	DWORD                SectionAlignment; // �޸𸮿����� ������ �ּҴ���
	DWORD                FileAlignment; // ���Ͽ����� ������ �ּҴ���
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage; // ���� �޸𸮿��� PE Image�� �����ϴ� ũ��(�ε��� ũ��)
	DWORD                SizeOfHeaders; // PE ����� ��ü ũ��(FileAlignment�� ���)
	DWORD                CheckSum;
	WORD                 Subsystem; // ����ý��� ���� ����
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes; // DataDirectory �迭�� ����
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // IMAGE_DATA_DIRECTORY ����ü�� �迭
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
		DWORD VirtualSize; // �޸𸮿��� ������ �����ϴ� ũ��
	} Misc;
	DWORD VirtualAddress; // �޸𸮿����� ������ ���� �ּ� (RVA)
	DWORD SizeOfRawData; // ���Ͽ��� ������ �����ϴ� ũ��
	DWORD PointerToRawData; // ���Ͽ��� ������ ���� ��ġ
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	DWORD Characteristics; // ������ Ư¡ (bit OR)
};

typedef struct _MY_IMAGE_EXPORT_DIRECTORY
{
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions; // export�ϴ� �Լ� ����
	DWORD NumberOfNames;
	DWORD AddressOfFunctions; // export �Լ� �ּ� �迭
	DWORD AddressOfNames; // �Լ� �̸� �ּ� �迭
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
		DWORD OriginalFirstThunk; // INT(Import Name Table) RVA �ּ�
	};
	DWORD TimeDataStamp;
	DWORD ForwarderChain;
	DWORD Name; // DLL �̸� RVA �ּ�
	DWORD FirstThunk; // IAT(Import Address Table) RVA �ּ�
}; 

typedef struct _MY_IMAGE_THUNK_DATA32
{
	union
	{
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal; // ����Ʈ�� �Լ��� ���� Ordinal ���� ����� �� ���
		DWORD AddressOfData; //_IMAGE_IMPORT_BY_NAME ����ü �ּ�
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