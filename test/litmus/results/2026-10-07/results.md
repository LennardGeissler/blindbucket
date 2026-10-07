| Test | minio | garage | seaweedfs | aws |
|---|---|---|---|---|
| `cond-put-inm` | enforced (5/5) | ignored (5/5) | enforced (5/5) | enforced (5/5) |
| `cond-put-im` | enforced (5/5) | ignored (5/5) | enforced (5/5) | enforced (5/5) |
| `cond-complete-im` | enforced (5/5) | ignored (5/5) | enforced (5/5) | enforced (5/5) |
| `cond-complete-inm` | enforced (5/5) | ignored (5/5) | enforced (5/5) | enforced (5/5) |
| `copy-source-im` | enforced (5/5) | enforced (5/5) | enforced (5/5) | enforced (5/5) |
| `overlap-mpu-mpu` | last-completed (5/5) | last-created; loser refused (404/NoSuchUpload) (5/5) | last-completed (5/5) | last-created; loser acknowledged (5/5) |
| `overlap-mpu-put` | last-completed (5/5) | last-begun; loser refused (404/NoSuchUpload) (5/5) | last-completed (5/5) | last-begun; loser acknowledged (5/5) |
| `read-after-write` | consistent (5/5) | consistent (5/5) | consistent (5/5) | consistent (5/5) |
| error inside a 200 | 0 seen | 0 seen | 0 seen | 0 seen |
