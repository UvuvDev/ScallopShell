#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ftxui::screen" for configuration "Debug"
set_property(TARGET ftxui::screen APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(ftxui::screen PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib64/libftxui-screen.a"
  )

list(APPEND _cmake_import_check_targets ftxui::screen )
list(APPEND _cmake_import_check_files_for_ftxui::screen "${_IMPORT_PREFIX}/lib64/libftxui-screen.a" )

# Import target "ftxui::dom" for configuration "Debug"
set_property(TARGET ftxui::dom APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(ftxui::dom PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib64/libftxui-dom.a"
  )

list(APPEND _cmake_import_check_targets ftxui::dom )
list(APPEND _cmake_import_check_files_for_ftxui::dom "${_IMPORT_PREFIX}/lib64/libftxui-dom.a" )

# Import target "ftxui::component" for configuration "Debug"
set_property(TARGET ftxui::component APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(ftxui::component PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib64/libftxui-component.a"
  )

list(APPEND _cmake_import_check_targets ftxui::component )
list(APPEND _cmake_import_check_files_for_ftxui::component "${_IMPORT_PREFIX}/lib64/libftxui-component.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
