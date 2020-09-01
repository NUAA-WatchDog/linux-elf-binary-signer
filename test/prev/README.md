# Performance Test Result

Created by : Mr Dk.

2020 / 09 / 01 16:41

---

The test runs several *GNU Core-Util* programs for 1000 times each, and calculate the total time from the start of execution to the termination, on a kernel with / without signature verification.

| ELF File | Without Signature Verification (μs) | With Signature Verification (μs) | Overhead |
| -------- | ----------------------------------- | -------------------------------- | -------- |
| cp       | 3013373                             | 6150166                          | 2.0410   |
| df       | 4031915                             | 6397411                          | 1.5867   |
| echo     | 2015491                             | 3531790                          | 1.7523   |
| false    | 1670998                             | 3142193                          | 1.8804   |
| grep     | 2726951                             | 7343783                          | 2.6930   |
| kill     | 4066986                             | 5582955                          | 1.3727   |
| less     | 2637721                             | 5661841                          | 2.1465   |
| ls       | 2765057                             | 5498167                          | 1.9884   |
| mkdir    | 2797265                             | 5024875                          | 1.7963   |
| mount    | 4353229                             | 5878047                          | 1.3503   |
| mv       | 3062660                             | 6194796                          | 2.0227   |
| rm       | 2186421                             | 4062839                          | 1.8582   |
| rmdir    | 2164469                             | 3794732                          | 1.7532   |
| tar      | 3348584                             | 10261805                         | 3.0645   |
| touch    | 2165813                             | 4495568                          | 2.0757   |
| true     | 1692813                             | 3146270                          | 1.8586   |
| umount   | 3341070                             | 4812077                          | 1.4403   |
| uname    | 2013237                             | 3526416                          | 1.7516   |

---

