add_library(webui INTERFACE)

target_sources(webui INTERFACE
 ${CMAKE_CURRENT_LIST_DIR}/commands.c
# ${CMAKE_CURRENT_LIST_DIR}/fs_embedded.c
 ${CMAKE_CURRENT_LIST_DIR}/login.c
 ${CMAKE_CURRENT_LIST_DIR}/sdcard.c
 ${CMAKE_CURRENT_LIST_DIR}/server.c
)
