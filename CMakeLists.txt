cmake_minimum_required(VERSION 3.0)
project (winibverbs)

set(HEADER_LIST include/comp_channel.h include/dlist.h include/infiniband/verbs.h include/rdma/winverbs.h include/rdma/wvstatus.h)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(winibverbs SHARED
	${HEADER_LIST}
	src/comp_channel.cpp
	src/device.cpp
	src/enum_strs.cpp
	src/ibv_main.cpp
	src/ibverbs.h
	src/ibverbs.rc
	src/oib_ver.h
	src/verbs.cpp
)

target_include_directories(winibverbs
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(winibverbs PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(winibverbs ws2_32.lib ${CMAKE_CURRENT_SOURCE_DIR}/lib/winverbs.lib)

install(TARGETS winibverbs)

install(FILES 
	include/comp_channel.h
	include/dlist.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES 
	include/infiniband/verbs.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/infiniband
)

install(FILES 
	include/rdma/winverbs.h
	include/rdma/wvstatus.h
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rdma
)