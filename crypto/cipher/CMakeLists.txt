include_directories(../../include)

add_library(
  cipher

  OBJECT

  cipher.c
  aead.c
  e_aes.c
)

add_executable(
  cipher_test

  cipher_test.cc
  $<TARGET_OBJECTS:test_support>
)

add_executable(
  aead_test

  aead_test.cc
  $<TARGET_OBJECTS:test_support>
)

target_link_libraries(cipher_test crypto)
target_link_libraries(aead_test crypto)
