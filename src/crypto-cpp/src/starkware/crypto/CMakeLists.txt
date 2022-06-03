add_subdirectory(ffi)

add_library(crypto elliptic_curve_constants.cc pedersen_hash.cc ecdsa.cc)
target_link_libraries(crypto algebra)

