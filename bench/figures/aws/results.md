```
date:        2026-10-05T13:29:17Z
host:        Linux 6.18.51-120.163.amzn2023.aarch64 aarch64
cpu:         
unknown
cores:       8
memory:      15671 MiB
go:          not installed
warp:        warp version 1.3.1 - 143bf4f
provider:    AWS S3 eu-central-1, from c7g.2xlarge in the same region; gateway 1.1.0
duration:    30s per run
sizes:       1KiB 10MiB 1GiB
concurrency: 1 16 64
```

| Size | Op | Clients | Direct | Through the proxy | Ratio | p50 direct → proxy | p99 direct → proxy |
|---|---|---:|---:|---:|---:|---:|---:|
| 1KiB | GET | 1 | 42 obj/s | 41 obj/s | 98% | 23.6 → 24.2 ms | 36.2 → 39.7 ms |
| 1KiB | GET | 16 | 677 obj/s | 665 obj/s | 98% | 23.5 → 23.9 ms | 35.0 → 34.9 ms |
| 1KiB | GET | 64 | 2,700 obj/s | 2,672 obj/s | 99% | 23.5 → 23.8 ms | 33.0 → 34.4 ms |
| 1KiB | PUT | 1 | 42 obj/s | 39 obj/s | 92% | 23.1 → 25.0 ms | 44.3 → 51.7 ms |
| 1KiB | PUT | 16 | 662 obj/s | 637 obj/s | 96% | 23.4 → 24.6 ms | 44.1 → 44.2 ms |
| 1KiB | PUT | 64 | 2,511 obj/s | 2,432 obj/s | 97% | 24.3 → 26.4 ms | 51.1 → 55.7 ms |
| 10MiB | GET | 1 | 91.2 MiB/s | 90.7 MiB/s | 100% | 106.7 → 107.3 ms | 177.2 → 151.3 ms |
| 10MiB | GET | 16 | 1488.4 MiB/s | 1484.2 MiB/s | 100% | 107.3 → 107.4 ms | 115.4 → 121.4 ms |
| 10MiB | GET | 64 | 1767.1 MiB/s | 1765.4 MiB/s | 100% | 305.1 → 333.4 ms | 2303.9 → 1960.3 ms |
| 10MiB | PUT | 1 | 77.6 MiB/s | 88.1 MiB/s | 114% | 128.8 → 112.5 ms | 151.8 → 136.3 ms |
| 10MiB | PUT | 16 | 1265.2 MiB/s | 1412.9 MiB/s | 112% | 124.7 → 111.6 ms | 190.9 → 141.0 ms |
| 10MiB | PUT | 64 | 1771.3 MiB/s | 1767.4 MiB/s | 100% | 360.8 → 341.3 ms | 555.7 → 1255.4 ms |
| 1GiB | GET | 1 | 95.3 MiB/s | 95.3 MiB/s | 100% | 10739.3 → 10742.7 ms | 10739.3 → 10742.7 ms |
| 1GiB | GET | 16 | 1524.2 MiB/s | 1523.7 MiB/s | 100% | 10744.3 → 10749.3 ms | 10784.6 → 10784.0 ms |
| 1GiB | GET | 64 | 1715.0 MiB/s | 1730.0 MiB/s | 101% | 28665.7 → 34767.6 ms | 36794.7 → 38569.7 ms |
| 1GiB | PUT | 1 | 327.9 MiB/s | 343.9 MiB/s | 105% | 3134.6 → 2984.2 ms | 3166.8 → 2987.7 ms |
| 1GiB | PUT | 16 | 1761.0 MiB/s | 1777.7 MiB/s | 101% | 8625.7 → 9321.6 ms | 13643.4 → 12979.7 ms |
| 1GiB | PUT | 64 | 1783.5 MiB/s | 1761.9 MiB/s | 99% | 38182.2 → 35388.0 ms | 41141.5 → 38135.4 ms |
