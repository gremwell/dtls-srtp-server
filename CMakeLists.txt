cmake_minimum_required(VERSION 3.5)

project(dtls-srtp-server LANGUAGES C)

find_package(GnuTLS REQUIRED)

set(prjSources
  dtls-srtp-server.c
  )

set(prjHeaders
  )

add_executable(dtls-srtp-server ${prjSources} ${prjHeaders})

include_directories(${dtls-srtp-server_INCLUDE_DIRECTORIES} ${GNUTLS_INCLUDE_DIR})
target_link_libraries(dtls-srtp-server ${GNUTLS_LIBRARIES})
