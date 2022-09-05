{
  "targets": [
    {
      "target_name": "libcrypto",
      "type": "shared_library",
      "sources": [
        "deps/crypto-cpp/src/starkware/crypto/pedersen_hash.cc",
        "deps/crypto-cpp/src/starkware/crypto/ffi/pedersen_hash.cc",
        "deps/crypto-cpp/src/starkware/crypto/ffi/utils.cc",
        "deps/crypto-cpp/src/starkware/crypto/ffi/ecdsa.cc",
        "deps/crypto-cpp/src/starkware/crypto/ecdsa.cc",
        "deps/crypto-cpp/src/starkware/crypto/elliptic_curve_constants.cc",
        "deps/crypto-cpp/src/starkware/starkex/order.cc",
        "deps/crypto-cpp/src/starkware/algebra/prime_field_element.cc"
      ],
      "include_dirs": ["deps/crypto-cpp/src"],
      "cflags_cc": ["-std=c++17", "-Wall", "-Wextra", "-fno-strict-aliasing", "-fPIC", "-fexceptions", "-O3"],
      "conditions": [
        [
          "OS==\"mac\"", {
            "xcode_settings": {
              "GCC_ENABLE_CPP_RTTI": "YES",
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
            }
          }
        ]
      ]
    }
  ]
}
