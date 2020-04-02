include_directories(${ROOTDIR}/public/libcrypto/include
					${ROOTDIR}/third/openssl/include)

link_directories(${ROOTDIR}/third/openssl/lib/x64)

IF (FP_TEST_FLAG)
	add_definitions(-DFP_TEST_FLAG)
ENDIF()

set(LIBNAME "libqinncrypt")
set(DEPENDLIBS libcrypto-1_1-x64.lib)
aux_source_directory(. SRC_LIST)
add_library(${LIBNAME} SHARED ${SRC_LIST} qinncrypt_api.def)

target_link_libraries(${LIBNAME} ${DEPENDLIBS})

set(DLLSRCPATH ${ROOTDIR}/win_build/public/libcrypto/src/Debug)
set(DLLDSTPATH ${ROOTDIR}/win_build/test/Debug)

add_custom_command(TARGET ${LIBNAME} POST_BUILD
	COMMAND xcopy \"${DLLSRCPATH}/libqinncrypt.dll\" \"${DLLDSTPATH}\" /F /Y)

#将${LIBNAME}工程组织到public目录下 
set_target_properties(${LIBNAME} PROPERTIES FOLDER "public")