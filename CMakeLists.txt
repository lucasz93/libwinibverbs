cmake_minimum_required(VERSION 3.0)
project (winibverbs)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(winibverbs SHARED
	src/comp_channel.cpp
	src/device.cpp
	src/enum_strs.cpp
	src/ibv_main.cpp
	src/ibverbs.h
	src/ibverbs.rc
	src/main.cpp
	src/oib_ver.h
	src/verbs.cpp
)

target_compile_definitions(winibverbs PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(winibverbs ws2_32.lib ../lib/winverbs)

install(TARGETS winibverbs DESTINATION ${CMAKE_INSTALL_PREFIX})
install(FILES 
	include/comp_channel.h
	include/dlist.h
	include/infiniband/verbs.h
	include/rdma/winverbs.h
	include/wvstatus.h
	DESTINATION include)