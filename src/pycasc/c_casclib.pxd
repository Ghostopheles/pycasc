from libcpp cimport bool

cdef extern from "Python.h":
    char *PyString_AsString(object)

cdef extern from "CascPort.h":
    cdef const int MAX_PATH

cdef extern from "CascLib.h":
    ctypedef unsigned long size_t
    ctypedef unsigned char BYTE
    ctypedef unsigned short USHORT
    ctypedef int LONG
    ctypedef unsigned int DWORD
    ctypedef long long LONGLONG
    ctypedef signed long long LONGLONG
    ctypedef signed long long *PLONGLONG
    ctypedef unsigned long long ULONGLONG
    ctypedef unsigned long long *PULONGLONG
    ctypedef void *HANDLE
    ctypedef char TCHAR
    ctypedef unsigned int LCID
    ctypedef LONG * PLONG
    ctypedef DWORD * PDWORD
    ctypedef BYTE * LPBYTE
    ctypedef char * LPSTR
    ctypedef const char * LPCSTR
    ctypedef TCHAR * LPTSTR
    ctypedef const TCHAR * LPCTSTR

    cdef const LPCSTR CASCLIB_VERSION_STRING

    cdef const unsigned int CASC_OPEN_BY_NAME
    cdef const unsigned int CASC_OPEN_BY_CKEY
    cdef const unsigned int CASC_OPEN_BY_EKEY
    cdef const unsigned int CASC_OPEN_BY_FILEID
    cdef const unsigned int CASC_OPEN_TYPE_MASK
    cdef const unsigned int CASC_OPEN_FLAGS_MASK
    cdef const unsigned int CASC_STRICT_DATA_CHECK
    cdef const unsigned int CASC_OVERCOME_ENCRYPTED
    cdef const unsigned int CASC_OPEN_CKEY_ONCE

    cdef const unsigned int CASC_LOCALE_ALL
    cdef const unsigned int CASC_LOCALE_ALL_WOW
    cdef const unsigned int CASC_LOCALE_NONE
    cdef const unsigned int CASC_LOCALE_UNKNOWN1
    cdef const unsigned int CASC_LOCALE_ENUS
    cdef const unsigned int CASC_LOCALE_KOKR
    cdef const unsigned int CASC_LOCALE_RESERVED
    cdef const unsigned int CASC_LOCALE_FRFR
    cdef const unsigned int CASC_LOCALE_DEDE
    cdef const unsigned int CASC_LOCALE_ZHCN
    cdef const unsigned int CASC_LOCALE_ESES
    cdef const unsigned int CASC_LOCALE_ZHTW
    cdef const unsigned int CASC_LOCALE_ENGB
    cdef const unsigned int CASC_LOCALE_ENCN
    cdef const unsigned int CASC_LOCALE_ENTW
    cdef const unsigned int CASC_LOCALE_ESMX
    cdef const unsigned int CASC_LOCALE_RURU
    cdef const unsigned int CASC_LOCALE_PTBR
    cdef const unsigned int CASC_LOCALE_ITIT
    cdef const unsigned int CASC_LOCALE_PTPT

    cdef const unsigned int CASC_CFLAG_INSTALL 
    cdef const unsigned int CASC_CFLAG_LOAD_ON_WINDOWS
    cdef const unsigned int CASC_CFLAG_LOAD_ON_MAC
    cdef const unsigned int CASC_CFLAG_X86_32
    cdef const unsigned int CASC_CFLAG_X86_64    
    cdef const unsigned int CASC_CFLAG_LOW_VIOLENCE
    cdef const unsigned int CASC_CFLAG_DONT_LOAD   
    cdef const unsigned int CASC_CFLAG_UPDATE_PLUGIN
    cdef const unsigned int CASC_CFLAG_ARM64       
    cdef const unsigned int CASC_CFLAG_ENCRYPTED
    cdef const unsigned int CASC_CFLAG_NO_NAME_HASH
    cdef const unsigned int CASC_CFLAG_UNCMN_RESOLUTION
    cdef const unsigned int CASC_CFLAG_BUNDLE
    cdef const unsigned int CASC_CFLAG_NO_COMPRESSION

    # Flags for CASC_STORAGE_FEATURES::dwFeatures
    cdef const unsigned int CASC_FEATURE_FILE_NAMES             # File names are supported by the storage
    cdef const unsigned int CASC_FEATURE_ROOT_CKEY              # Present if the storage's ROOT returns CKey
    cdef const unsigned int CASC_FEATURE_TAGS                   # Tags are supported by the storage
    cdef const unsigned int CASC_FEATURE_FNAME_HASHES           # The storage contains file name hashes on ALL files
    cdef const unsigned int CASC_FEATURE_FNAME_HASHES_OPTIONAL  # The storage contains file name hashes for SOME files
    cdef const unsigned int CASC_FEATURE_FILE_DATA_IDS          # The storage indexes files by FileDataId
    cdef const unsigned int CASC_FEATURE_LOCALE_FLAGS           # Locale flags are supported
    cdef const unsigned int CASC_FEATURE_CONTENT_FLAGS          # Content flags are supported
    cdef const unsigned int CASC_FEATURE_DATA_ARCHIVES          # The storage supports files stored in data.### archives
    cdef const unsigned int CASC_FEATURE_DATA_FILES             # The storage supports raw files stored in %CascRoot%\xx\yy\xxyy## (CKey-based)
    cdef const unsigned int CASC_FEATURE_ONLINE                 # Load the missing files from online CDNs
    cdef const unsigned int CASC_FEATURE_FORCE_DOWNLOAD         # (Online) always download "versions" and "cdns" even if it exists locally

    cdef const unsigned int CASC_KEY_LENGTH

    cdef const int MD5_HASH_SIZE
    cdef const int MD5_STRING_SIZE

    cdef const int SHA1_HASH_SIZE
    cdef const int SHA1_STRING_SIZE

    # Some storages support multi-product installation (e.g. World of Warcraft).
    # With this callback, the calling application can specify which storage to open
    ctypedef bool (* PFNPRODUCTCALLBACK)\
    (
        void * PtrUserParam,
        LPCSTR * ProductList,
        size_t ProductCount,
        size_t * PtrSelectedProduct
    )

    # Some operations (e.g. opening an online storage) may take long time.
    # This callback allows an application to be notified about loading progress
    # and even cancel the storage loading process
    ctypedef bool (* PFNPROGRESSCALLBACK)\
    (
        void * PtrUserParam,
        LPCSTR szWork,
        LPCSTR szObject,
        DWORD CurrentValue,
        DWORD TotalValue
    )

    # Returns the number of local files in the storage. Note that files
    # can exist under different names, so the total number of files in the archive
    # can be higher than the value returned by this info class
    ctypedef enum CASC_STORAGE_INFO_CLASS:
        CascStorageLocalFileCount,
        CascStorageTotalFileCount,
        CascStorageFeatures,          # Returns the features flag
        CascStorageInstalledLocales,  # Not supported
        CascStorageProduct,           # Gives CASC_STORAGE_PRODUCT
        CascStorageTags,              # Gives CASC_STORAGE_TAGS structure
        CascStoragePathProduct,       # Gives Path:Product into a LPTSTR buffer
        CascStorageInfoClassMax

    ctypedef CASC_STORAGE_INFO_CLASS* PCASC_STORAGE_INFO_CLASS


    ctypedef struct CASC_OPEN_STORAGE_ARGS:
        size_t Size
        LPCTSTR szLocalPath
        LPCTSTR szCodeName
        LPCTSTR szRegion
        PFNPROGRESSCALLBACK PfnProgressCallback
        void * PtrProgressParam
        PFNPRODUCTCALLBACK PfnProductCallback
        void * PtrProductParam
        DWORD dwLocaleMask
        DWORD dwFlags
        LPCTSTR szBuildKey
        LPCTSTR szCdnHostUrl        # If non-null, specifies the custom CDN URL. Must contain protocol, can contain port number
                                    # Example: http:#eu.custom-wow-cdn.com:8000

    ctypedef CASC_OPEN_STORAGE_ARGS* PCASC_OPEN_STORAGE_ARGS


    ctypedef enum CASC_FILE_INFO_CLASS:
        CascFileContentKey,
        CascFileEncodedKey,
        CascFileFullInfo,                           # Gives CASC_FILE_FULL_INFO structure
        CascFileSpanInfo,                           # Gives CASC_FILE_SPAN_INFO structure for each file span
        CascFileInfoClassMax

    ctypedef CASC_FILE_INFO_CLASS* PCASC_FILE_INFO_CLASS


    ctypedef enum CASC_NAME_TYPE:
        CascNameFull,
        CascNameDataId,
        CascNameCKey,
        CascNameEKey
        
    ctypedef CASC_NAME_TYPE* PCASC_NAME_TYPE


    ctypedef struct CASC_FILE_FULL_INFO:
        BYTE[MD5_HASH_SIZE] CKey                   # CKey
        BYTE[MD5_HASH_SIZE] EKey                   # EKey
        char[0x10] DataFileName           # Plain name of the data file where the file is stored
        ULONGLONG StorageOffset                    # Offset of the file over the entire storage
        ULONGLONG SegmentOffset                    # Offset of the file in the segment file ("data.###")
        ULONGLONG TagBitMask                       # Bitmask of tags. Zero if not supported
        ULONGLONG FileNameHash                     # Hash of the file name. Zero if not supported
        ULONGLONG ContentSize                      # Content size of all spans
        ULONGLONG EncodedSize                      # Encoded size of all spans
        DWORD SegmentIndex                         # Index of the segment file (aka 0 = "data.000")
        DWORD SpanCount                            # Number of spans forming the file
        DWORD FileDataId                           # File data ID. CASC_INVALID_ID if not supported.
        DWORD LocaleFlags                          # Locale flags. CASC_INVALID_ID if not supported.
        DWORD ContentFlags                         # Locale flags. CASC_INVALID_ID if not supported


    ctypedef struct CASC_FIND_DATA:
        # Full name of the found file. In case when this is CKey/EKey,
        # this will be just string representation of the key stored in 'FileKey'
        char[MAX_PATH] szFileName

        # Content key. This is present if the CASC_FEATURE_ROOT_CKEY is present
        BYTE[MD5_HASH_SIZE] CKey

        # Encoded key. This is always present.
        BYTE[MD5_HASH_SIZE] EKey

        # Tag mask. Only valid if the storage supports tags, otherwise 0
        ULONGLONG TagBitMask

        # Size of the file, as retrieved from CKey entry
        ULONGLONG FileSize

        # Plain name of the found file. Pointing inside the 'szFileName' array
        char * szPlainName

        # File data ID. Only valid if the storage supports file data IDs, otherwise CASC_INVALID_ID
        DWORD dwFileDataId

        # Locale flags. Only valid if the storage supports locale flags, otherwise CASC_INVALID_ID
        DWORD dwLocaleFlags

        # Content flags. Only valid if the storage supports content flags, otherwise CASC_INVALID_ID
        DWORD dwContentFlags

        # Span count
        DWORD dwSpanCount

        # If true the file is available locally
        DWORD bFileAvailable

        # Name type in 'szFileName'. In case the file name is not known,
        # CascLib can put FileDataId-like name or a string representation of CKey/EKey
        CASC_NAME_TYPE NameType

    ctypedef CASC_FIND_DATA* PCASC_FIND_DATA

    bool CascOpenStorageEx(LPCTSTR szParams, PCASC_OPEN_STORAGE_ARGS pArgs, bool bOnlineStorage, HANDLE *phStorage)
    bool CascOpenStorage(LPCTSTR szParams, DWORD dwLocaleMask, HANDLE *phStorage)
    bool CascOpenOnlineStorage(LPCTSTR szParams, DWORD dwLocaleMask, HANDLE *phStorage)
    bool CascGetStorageInfo(HANDLE hStorage, CASC_STORAGE_INFO_CLASS InfoClass, void *pvStorageInfo, size_t cbStorageInfo, size_t *pcbLengthNeeded)
    bool CascCloseStorage(HANDLE hStorage)

    bool CascOpenFile(HANDLE hStorage, const void * pvFileName, DWORD dwLocaleFlags, DWORD dwOpenFlags, HANDLE * PtrFileHandle)
    bool CascOpenLocalFile(LPCTSTR szFileName, DWORD dwOpenFlags, HANDLE * PtrFileHandle)
    bool CascGetFileInfo(HANDLE hFile, CASC_FILE_INFO_CLASS InfoClass, void * pvFileInfo, size_t cbFileInfo, size_t * pcbLengthNeeded)
    bool CascSetFileFlags(HANDLE hFile, DWORD dwOpenFlags)
    bool CascGetFileSize64(HANDLE hFile, PULONGLONG PtrFileSize)
    bool CascSetFilePointer64(HANDLE hFile, LONGLONG DistanceToMove, PULONGLONG PtrNewPos, DWORD dwMoveMethod)
    bool CascReadFile(HANDLE hFile, void * lpBuffer, DWORD dwToRead, PDWORD pdwRead)
    bool CascCloseFile(HANDLE hFile)

    DWORD CascGetFileSize(HANDLE hFile, PDWORD pdwFileSizeHigh)
    DWORD CascSetFilePointer(HANDLE hFile, LONG lFilePos, LONG * PtrFilePosHigh, DWORD dwMoveMethod)

    HANDLE CascFindFirstFile(HANDLE hStorage, LPCSTR szMask, PCASC_FIND_DATA pFindData, LPCTSTR szListFile)
    bool CascFindNextFile(HANDLE hFind, PCASC_FIND_DATA pFindData)
    bool CascFindClose(HANDLE hFind)

    bool CascAddEncryptionKey(HANDLE hStorage, ULONGLONG KeyName, LPBYTE Key)
    bool CascAddStringEncryptionKey(HANDLE hStorage, ULONGLONG KeyName, LPCSTR szKey)
    bool CascImportKeysFromString(HANDLE hStorage, LPCSTR szKeyList)
    bool CascImportKeysFromFile(HANDLE hStorage, LPCTSTR szFileName)
    LPBYTE CascFindEncryptionKey(HANDLE hStorage, ULONGLONG KeyName)
    bool CascGetNotFoundEncryptionKey(HANDLE hStorage, ULONGLONG * KeyName)

    # -----------------------------------------------------------------------------
    #  CDN Support

    LPCTSTR CascCdnGetDefault()
    LPBYTE CascCdnDownload(LPCTSTR szCdnHostUrl, LPCTSTR szProduct, LPCTSTR szFileName, DWORD * PtrSize)
    void CascCdnFree(void * buffer)

    # -----------------------------------------------------------------------------
    #  Error code support

    void SetCascError(DWORD dwErrCode)
    DWORD GetCascError()