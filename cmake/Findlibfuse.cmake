# Locate libfuse
#
# When found defines:
#
#   LIBFUSE_FOUND        - libfuse has been found
#   LIBFUSE_INCLUDE_DIRS - libfuse include directories
#   LIBFUSE_LIBRARIES    - libfuse libraries
#
# CMake cache entries:
#
#   LIBFUSE_INCLUDE_DIR  - detected libfuse include directory
#   LIBFUSE_LIBRARY      - detected libfuse library

if(LIBFUSE_INCLUDE_DIR AND LIBFUSE_LIBRARY)
	# Use cached values if available
	set(LIBFUSE_FOUND TRUE)
	set(LIBFUSE_INCLUDE_DIRS ${LIBFUSE_INCLUDE_DIR})
	set(LIBFUSE_LIBRARIES    ${LIBFUSE_LIBRARY})
else()
	# Use pkg-config if available
	find_package(PkgConfig)
	if(PKG_CONFIG_FOUND)
		pkg_check_modules(_LIBFUSE_PC QUIET "fuse")
	endif()

	# Locate and cache include directory
	find_path(LIBFUSE_INCLUDE_DIR fuse/fuse.h
		${_LIBFUSE_PC_INCLUDE_DIRS}
		/usr/include
		/usr/local/include
	)
	mark_as_advanced(LIBFUSE_INCLUDE_DIR)

	# Locate and cache library paths
	find_library(LIBFUSE_LIBRARY
		NAMES fuse
		PATHS
			${_LIBFUSE_PC_LIBDIR}
			/usr/lib
			/usr/local/lib
	)
	mark_as_advanced(LIBFUSE_LIBRARY)

	# Provide found locations
	include(FindPackageHandleStandardArgs)
	find_package_handle_standard_args(libfuse DEFAULT_MSG LIBFUSE_LIBRARY LIBFUSE_INCLUDE_DIR)

	if(LIBFUSE_FOUND)
		set(LIBFUSE_INCLUDE_DIRS ${LIBFUSE_INCLUDE_DIR})
		set(LIBFUSE_LIBRARIES    ${LIBFUSE_LIBRARY})
	endif()
endif()
