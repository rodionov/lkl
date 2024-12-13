Binder fuzzer is based on `libprotobuf-mutator`. Thus, follow instructions at
https://github.com/google/libprotobuf-mutator in order to download, build and
install `libprotobuf-mutator` and `libprotobuf` dependencies.

Before building the fuzzer run `tools/lkl/fuzzers/binder/compile_proto.sh` to
generate `binder.pb.cpp` and `binder.pb.h` from `binder.proto`.

To build the fuzzer run the following commands from the root of LKL source tree:

```
make -C tools/lkl LKL_FUZZING=1 clean-conf
make -C tools/lkl LKL_FUZZING=1 binder_fuzzer
```

The fuzzer binary is generated at `tools/lkl/fuzzers/binder/binder-fuzzer`.