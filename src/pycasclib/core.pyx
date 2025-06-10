from libcpp cimport bool
from libc.stdlib cimport free, malloc
from libc.string cimport strcpy

from typing import Union, Tuple, Optional
from dataclasses import dataclass

cimport pycasclib.c_casclib as casclib
from pycasclib.c_casclib cimport *

ERROR_STR_MAP = {
    ERROR_SUCCESS: "ERROR_SUCCESS",
    ERROR_PATH_NOT_FOUND: "ERROR_PATH_NOT_FOUND",
    ERROR_ACCESS_DENIED: "ERROR_ACCESS_DENIED",
    ERROR_INVALID_HANDLE: "ERROR_INVALID_HANDLE",
    ERROR_NOT_ENOUGH_MEMORY: "ERROR_NOT_ENOUGH_MEMORY",
    ERROR_NOT_SUPPORTED: "ERROR_NOT_SUPPORTED",
    ERROR_INVALID_PARAMETER: "ERROR_INVALID_PARAMETER",
    ERROR_DISK_FULL: "ERROR_DISK_FULL",
    ERROR_ALREADY_EXISTS: "ERROR_ALREADY_EXISTS",
    ERROR_INSUFFICIENT_BUFFER:  "ERROR_INSUFFICIENT_BUFFER",
    ERROR_BAD_FORMAT: "ERROR_BAD_FORMAT",
    ERROR_NO_MORE_FILES: "ERROR_NO_MORE_FILES",
    ERROR_HANDLE_EOF: "ERROR_HANDLE_EOF",
    ERROR_CAN_NOT_COMPLETE: "ERROR_CAN_NOT_COMPLETE",
    ERROR_FILE_CORRUPT: "ERROR_FILE_CORRUPT",
    ERROR_FILE_ENCRYPTED: "ERROR_FILE_ENCRYPTED",
    ERROR_FILE_INCOMPLETE: "ERROR_FILE_INCOMPLETE",
    ERROR_FILE_OFFLINE: "ERROR_FILE_OFFLINE",
    ERROR_BUFFER_OVERFLOW: "ERROR_BUFFER_OVERFLOW",
    ERROR_CANCELLED: "ERROR_CANCELLED",
}

class CascLibException(Exception):
    error_code: int

    def __init__(self, error_code: int, message: Optional[str] = None):
        self.add_note(ERROR_STR_MAP.get(error_code))
        
        if message is not None:
            self.add_note(message)


class FileOpenFlags:
    CASC_OPEN_BY_NAME = casclib.CASC_OPEN_BY_NAME
    CASC_OPEN_BY_CKEY = casclib.CASC_OPEN_BY_CKEY
    CASC_OPEN_BY_EKEY = casclib.CASC_OPEN_BY_EKEY
    CASC_OPEN_BY_FILEID = casclib.CASC_OPEN_BY_FILEID
    CASC_OPEN_TYPE_MASK = casclib.CASC_OPEN_TYPE_MASK
    CASC_OPEN_FLAGS_MASK = casclib.CASC_OPEN_FLAGS_MASK
    CASC_STRICT_DATA_CHECK = casclib.CASC_STRICT_DATA_CHECK
    CASC_OVERCOME_ENCRYPTED = casclib.CASC_OVERCOME_ENCRYPTED
    CASC_OPEN_CKEY_ONCE = casclib.CASC_OPEN_CKEY_ONCE


class LocaleFlags:
    CASC_LOCALE_ALL = casclib.CASC_LOCALE_ALL
    CASC_LOCALE_NONE = casclib.CASC_LOCALE_NONE
    CASC_LOCALE_UNKNOWN1 = casclib.CASC_LOCALE_UNKNOWN1
    CASC_LOCALE_ENUS = casclib.CASC_LOCALE_ENUS
    CASC_LOCALE_KOKR = casclib.CASC_LOCALE_KOKR
    CASC_LOCALE_RESERVED = casclib.CASC_LOCALE_RESERVED
    CASC_LOCALE_FRFR = casclib.CASC_LOCALE_FRFR
    CASC_LOCALE_DEDE = casclib.CASC_LOCALE_DEDE
    CASC_LOCALE_ZHCN = casclib.CASC_LOCALE_ZHCN
    CASC_LOCALE_ESES = casclib.CASC_LOCALE_ESES
    CASC_LOCALE_ZHTW = casclib.CASC_LOCALE_ZHTW
    CASC_LOCALE_ENGB = casclib.CASC_LOCALE_ENGB
    CASC_LOCALE_ENCN = casclib.CASC_LOCALE_ENCN
    CASC_LOCALE_ENTW = casclib.CASC_LOCALE_ENTW
    CASC_LOCALE_ESMX = casclib.CASC_LOCALE_ESMX
    CASC_LOCALE_RURU = casclib.CASC_LOCALE_RURU
    CASC_LOCALE_PTBR = casclib.CASC_LOCALE_PTBR
    CASC_LOCALE_ITIT = casclib.CASC_LOCALE_ITIT
    CASC_LOCALE_PTPT = casclib.CASC_LOCALE_PTPT

@dataclass
class FileInfoFull:
    ckey: bytes
    ekey: bytes
    dataFileName: str
    storageOffset: int
    segmentOffset: int
    tagBitMask: int
    fileNameHash: int
    contentSize: int
    encodedSize: int
    segmentIndex: int
    spanCount: int
    fileDataID: int
    localeFlags: int
    contentFlags: int


def _last_error():
    return CascLibException(GetCascError())

cdef void _open_file_handle(void* storage_handle, identifier: Union[str, int, bytes], open_flags: int, locale_flags: int, void** file_handle):
    cdef char* filePath
    cdef LPCSTR fileDataId
    cdef BYTE[MD5_HASH_SIZE] key

    if open_flags & FileOpenFlags.CASC_OPEN_BY_NAME:
        key = identifier.encode('utf-8') # file path
        if not casclib.CascOpenFile(storage_handle, key, locale_flags, open_flags, file_handle):
            raise CascLibException(ERROR_PATH_NOT_FOUND)
    elif open_flags & FileOpenFlags.CASC_OPEN_BY_FILEID:
        fileDataId = <LPCSTR><size_t>identifier
        if not casclib.CascOpenFile(storage_handle, fileDataId, locale_flags, open_flags, file_handle):
            raise CascLibException(ERROR_PATH_NOT_FOUND)
    elif open_flags & FileOpenFlags.CASC_OPEN_BY_CKEY or open_flags & FileOpenFlags.CASC_OPEN_BY_EKEY:
        if len(identifier) != MD5_HASH_SIZE:
            raise CascLibException(ERROR_INVALID_PARAMETER, message=f"CKey or EKey must be a bytes object with length {MD5_HASH_SIZE}")
        if not casclib.CascOpenFile(storage_handle, key, locale_flags, open_flags, file_handle):
            raise CascLibException(ERROR_PATH_NOT_FOUND)


cdef class CascFile:
    cdef void* file_handle
    cdef bytes raw_data
    cdef CascHandler storage
    cdef object file_info

    def __cinit__(self, storage: CascHandler, identifier: Union[str, int, bytes], open_flags: int):
        _open_file_handle(storage.storage_handle, identifier, open_flags, storage.locale_flags, &self.file_handle)

        self.storage = storage
        self.storage.open_files.add(self)

        self.raw_data = None
        self.file_info = None

    def close(self):
        """Closes the file."""
        self._close_file()
        self.storage.open_files.remove(self)


    def _close_file(self):
        CascCloseFile(self.file_handle)

    @property
    def info(self) -> FileInfoFull:
        if self.file_info is not None:
            return self.file_info

        cdef void* file_info_raw = <void*>malloc(sizeof(CASC_FILE_FULL_INFO))

        CascGetFileInfo(self.file_handle, CASC_FILE_INFO_CLASS.CascFileFullInfo,
                             file_info_raw, sizeof(CASC_FILE_FULL_INFO), NULL)

        cdef CASC_FILE_FULL_INFO* file_info = <CASC_FILE_FULL_INFO*>file_info_raw

        free(file_info_raw)

        py_file_info = FileInfoFull(
            file_info.CKey,
            file_info.EKey,
            file_info.FileDataId,
            file_info.ContentFlags,
            file_info.LocaleFlags,
            file_info.ContentSize,
            file_info.EncodedSize,
            file_info.DataFileName,
            file_info.FileNameHash,
            file_info.SegmentIndex,
            file_info.SegmentOffset,
            file_info.StorageOffset,
            file_info.SpanCount,
            file_info.TagBitMask,
        )

        self.file_info = py_file_info

        return py_file_info

    @info.setter
    def info(self, value):
        raise PermissionError('\nFile info is a read-only property.')

    @info.deleter
    def info(self):
        raise PermissionError('\nFile info is a read-only property.')

    @property
    def data(self):
        if self.raw_data is not None:
            return self.raw_data

        cdef DWORD file_size = CascGetFileSize(self.file_handle, NULL)
        cdef DWORD bytes_read
        cdef char *data = <char*>malloc(file_size)

        CascReadFile(self.file_handle, data, file_size, &bytes_read)

        if not bytes_read:
            raise _last_error()

        if bytes_read < file_size:
            raise CascLibException(ERROR_FILE_ENCRYPTED)

        self.raw_data = memoryview(data[:bytes_read]).tobytes()
        free(data)

        return self.raw_data

    @data.setter
    def data(self, other):
        raise PermissionError('\nData is a read-only property.')

    @data.deleter
    def data(self):
        raise PermissionError('\nData is a read-only property.')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

cdef class CascHandler:
    cdef void* storage_handle
    cdef long long locale_flags
    cdef set open_files
    cdef CASC_OPEN_STORAGE_ARGS p_args

    cdef char* cache_path
    cdef char* region
    cdef char* product

    def __cinit__(self, path: str, locale_flags: int = CASC_LOCALE_ENUS, product: str = "wow", region: str = "us", is_online: bool = False):
        """Initializes a CASC handle and opens CASC storage at the given path.
            If `is_online` == True, path points to the local storage cache"""
        self.open_files = set()
        self.locale_flags = locale_flags

        self.cache_path = <char*>malloc(len(path) + 1)
        strcpy(self.cache_path, path.encode('ascii'))

        self.region = <char*>malloc(len(region) + 1)
        strcpy(self.region, region.encode('ascii'))

        self.product = <char*>malloc(len(product) + 1)
        strcpy(self.product, product.encode('ascii'))

        self.p_args.Size = sizeof(CASC_OPEN_STORAGE_ARGS)
        self.p_args.szLocalPath = self.cache_path
        self.p_args.szCodeName = self.product
        self.p_args.szRegion = self.region
        self.p_args.dwLocaleMask = locale_flags

        if not CascOpenStorageEx(NULL, &self.p_args, is_online, &self.storage_handle):
            raise _last_error()

    @staticmethod
    def _identifier_to_open_flags(identifier: Union[str, int, bytes]) -> Optional[FileOpenFlags]:
        if isinstance(identifier, str):
            return FileOpenFlags.CASC_OPEN_BY_NAME
        elif isinstance(identifier, int):
            return FileOpenFlags.CASC_OPEN_BY_FILEID
        elif isinstance(identifier, bytes):
            return None
    
    def read_file(self, identifier: Union[str, int, bytes], open_flags: int) -> CascFile:
        return CascFile(self, identifier, open_flags)

    def read_file_by_id(self, fileID: int, open_flags: Optional[int] = CASC_OPEN_BY_FILEID) -> CascFile:
        return self.read_file(fileID, open_flags)

    def read_file_by_name(self, file_name: str, open_flags: Optional[int] = CASC_OPEN_BY_NAME) -> CascFile:
        return self.read_file(file_name, open_flags)

    def read_file_by_ckey(self, ckey: int, open_flags: Optional[int] = CASC_OPEN_BY_CKEY) -> CascFile:
        return self.read_file(ckey, open_flags)

    def read_file_by_ekey(self, ekey: int, open_flags: Optional[int] = CASC_OPEN_BY_EKEY) -> CascFile:
        return self.read_file(ekey, open_flags)

    def file_exists(self, identifier: Union[str, int, bytes], open_flags: Optional[int] = None) -> bool:
        cdef void* file_handle

        if open_flags is None:
            open_flags = self._identifier_to_open_flags(identifier)
        
        if open_flags is None:
            raise ValueError("open_flags is required when using an identifier of type 'bytes'")

        try:
            _open_file_handle(self.storage_handle, identifier, open_flags, self.locale_flags, &file_handle)
        except FileNotFoundError:
            return False
        except CascLibException:
            return False

        CascCloseFile(file_handle)

        return True

    def close(self):
        """Closes the CASC storage handle."""

        for file in self.open_files:
            file._close_file()

        self.open_files.clear()

        if self.storage_handle != NULL:
            CascCloseStorage(self.storage_handle)

    def __contains__(self, item: Tuple[Union[str, int, bytes], int]):
        return self.file_exists(item[0], item[1])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()