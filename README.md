# PKEET-FDA-Revisited

This is the implementation accompanying the paper "CCA2 Attack and Modification of Lin et al.'s PKEET-FDA".
It contains the PKEET-FDA scheme of Lin et al. (IEEE Systems Journal, 2022) and the modified scheme proposed in the paper, together with correctness tests, demonstrations of the attacks, and benchmarks.

## Requirements

```
sudo apt install build-essential cmake git perl
```

## Build

```
./build.sh
cmake -S . -B build
cmake --build build -j
```

`./build.sh` fetches and builds the pinned OpenSSL into `out/install`, and the CMake commands build the project against it. Run `./build.sh -h` for its targets and options.

To use a system OpenSSL (3.0 or later) instead, skip `./build.sh` and run:

```
cmake -S . -B build -DPKEET_USE_SYSTEM_OPENSSL=ON
cmake --build build -j
```

Use a separate build directory when switching between the two.

## Run

Tests:

```
./build/pkeet_test
```

This checks the correctness of both schemes and runs the attacks described in the paper, which succeed against the scheme of Lin et al. and fail against the modified scheme.

Benchmark:

```
cd build
./pkeet_bench -o pkeet_bench.csv
```

The results are written to `build/pkeet_bench.csv`. For stable measurements, pin the benchmark to a single core, e.g., `taskset -c <core> ./pkeet_bench`. Run `./pkeet_bench -h` for options.