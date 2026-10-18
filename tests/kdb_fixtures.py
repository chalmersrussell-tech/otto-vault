"""Fixtures made by an INDEPENDENT KeePass 1 implementation (the `kppy` library),
so the reader is checked against something other than itself. Throwaway data and
passwords only. KDB_PW opens KDB_PASSWORD_ONLY and KDB_BOTH; KDB_KEYONLY needs only
the key file. Contents (all three): group "Internet" with
  "Site One" / alice / p@ss"w0rd;<>&' / https://one.example / "note line1\\nline2"
  "Ünï Tïtle ✓" / bób / pässwörd✓
and an entry "Old thing" in the "Backup" group (skipped by the importer)."""
import base64

KDB_PW = "hunter2-throwaway"
KDB_PASSWORD_ONLY = base64.b64decode(
    "A9mimmX7S7UCAAAAAgADAOlphtWBTtkMGJwbWyhxIjxYwCoCNFazNgL1OIWWfke+AwAAAAMAAAAE"
    "EXbjbx9aY3v8sETF+BXpWltfBn/+bUaIdGQ7qihFlxIEWyI0jvwAiDzIryUsX+f0K5Ge2ZbXXrOF"
    "qXFGqTmf8EkCAEL7iXBLPm+TMyqErqOtRadndFmxDbyjXLZekNRRNSMedOXvUAx0vJd30IXN5j2j"
    "k6LroMxmLuBcr6TkHxQrNH+Q1BZ+YL7mrUhZtLUcB8FLkcCVbQp0V2Z4j2T/aDDw0i8eEaGif0Fq"
    "rDMQRZKoGuiZKYCvSjWhfHx+r3oxuROQJQgIF5M1hjbjIJHr9RAYMhjWOmlLz0SIJ17gZ+Q9Dllj"
    "XhHFl7On8EvxFakLdTLgHwonkuGeQP1BwFCs7d1x0y/uXLXciRLViF91Nul2UdD1P7SIKyVl5dKm"
    "Wcy2g02z/82wsKcvKrTe8Bl/cRpY3nQMujS+qVJ3ayyk9RNqpW/nidOVmj3au6QmW9TOvoFDgpAt"
    "K396Vho3qZuVhSbmmfaR/LgK5vperlF3HsL8gYQCh7KNaDNC5iYUSWYtpLkOHza6SrBkQFDblyQh"
    "qX6mPFy8EJazpZwIVCWni3MyF435X6qmgcrrfKc9uxymoewMjbC0OXYFLDrVXFpx6nuVbZZNOwBe"
    "J/iDugsgLGgFQr9aiqsW+s3pOhm6iFAQS2nVrmswkuBMXmPe09gABTt0hL4atKIXkS+jHQ2+guMb"
    "+UCQk12ZJhMtoIW4pgV4SDidjzedQzAaDdpWvBTulKiduY8F+D/ic/X8lubS8pxqN9jn5JYzF0Jr"
    "9bL4T/pgB2z1aNy6C79f8emRumAnM4Rd9u9Nd/lfuQkZ87Zi6oyw0UvKB1tiS7XOweaf2+Judxmk"
    "ZvzEH0J8A7ZqUvwS7SIbUxA6M1J/yfq6dV8ogdYILrDm40QvX+rjiaqNt66Mm0Gej5bao6Cq1U70"
    "6bOG8cbJUbcZSDkw2a6tayegjn5NAX3UCFnMA4X9klXrk4FdJbQ7E1+hYnkVHYrDD4hD8H/xgZoS"
    "rfWrQF/1Tk8ov8DtNxzCVEaLH+uwdccCzf5z2NmGN9Ueuk2pLIpCxAgVeWOX1OjhldyCdA9KZCLL"
    "4x2fA2k=")
KDB_BOTH = base64.b64decode(
    "A9mimmX7S7UCAAAAAgADABc6pZ55eoWn8BZql8eBt4fW+XZci4sbm2cdFtao956NAwAAAAMAAAAa"
    "H/tEzqGtMp/bOs9ShP+qzqgi5MuRBMUnFDIACZKj5T7PqIRSZ/3CmVRzvjw1UzjOUSfCNh2H3yo1"
    "z5p1cC7g8EkCAAg/dvY/gtzddWsZj8sTVwoyPJZbhwDph7am35Basu7u0VcvHiDbrDE/NwOyp3bQ"
    "l/tqgBKIKusOtRrSG2u3moN3aw/MZjhCUtreb7N0tc3BM5yzCTWuku/Vb8fXRTVYoUZwejPNrSeG"
    "ZHzowVydzi0FUbYlZS01vphlERZ9Z5s/fx5p8Sy1Qvr+c5n/U9fbo0EpvYRYm/rzG8CI/qsz88bE"
    "4o8EVMaqgYRNsl618bm4S58TW696QnMJgUN8atUOnmM2gpaNKA1CGYThyIQNhDUioo5UQjR6hRQg"
    "PhEdh3zwYMgmfKZfqP+VhcLt/aPNEakDEEM0A/KblmnBFc7IRxt/vxhJGF01ZhxBkjdZioQ84+Ws"
    "7yJsPUOihiwCDDhneldmgsXg4adfSkTFBYPMoGt54NqvP3Q77zkwybeGJSp0XX94v/40zBE0VPJc"
    "igQZUAXefuy0KY47NzCbMdiYskbnwleODTbKRyZYEI2NMcL4JBE3m/4oN4JE8lLRghb9+S77bxwz"
    "ayE/r0AJgwhsQYTlUXPxXHXS0pYlbgbYrbVVCiRbVA9I+QD8pjjpbHurOm6YA8hPMSPl0w9cHAFw"
    "1FvgjEjgd2kTSj0qDXa5vmIc8dACXmBay7OPl5uSOxwOSXBcpQjokfmCLG3YgHJYLdieh6X3yVVO"
    "OvmvQ5/fyhplRsOUaC23rRh5aJiXlsQxs8L2fphkXMDQeAAE+0t/KxAAX11PTEDlgfENDJJhPw4k"
    "SNyM+4UzMFHsgSdmfzu1P1jTNPXRE9EKTqXy8VsrbSNVe0l1T5HouJhx7FB+IFfhQ3dhL2RzJJFv"
    "T+vCaHmuLjqDmCb0mfPJ1qyMQyBi0fHl3gGX/0aaYbL1OsUhY2UCDT1YT6lp3Xi51rRM0d3ZpbWq"
    "yHjVid+V+XkicqWzKw6gMB9ZhJEy+PeQ8iuqYS1peUz3hebBkPNCFVQepY+JWWfqUqdkhoq6g5oI"
    "qIqI5XE=")
KDB_KEYONLY = base64.b64decode(
    "A9mimmX7S7UCAAAAAgADAEKrlXoSPVmRkxWSgiFf76XyhEo6yEQmIADV5uxroFsaAwAAAAMAAACh"
    "kEaIAQ4w+tSfEhgsdDAD0pJIjsmQcHkIlQ1UVDpqbQP4juNBrZvEJ4sty9GQNtV2cFnIWGQTWQqZ"
    "siUCxK4n8EkCAPBpcyhdbYOA4TgDqThIFCXPp66k+mGFPBi6PfA3caKvH7uOJy+FrZNqas+OvffL"
    "vn8rPUCLC7lfLJ09Jh0TOY584L0NHGp4O6YZwKz5d6bwz5flGTzdEiwY8JpY2BnvSvmV8auXXfVh"
    "0brGCQ6FSyb1/f4lXV0O+xINwVfRLMLFpq7E/0xfkWiiDBjRhslmdcBoM8fNu3WGctWpgHHO9JYc"
    "kgcv6ZB0DPZvSejnrMy+CYQX9ZhIbeJ588fzIZ0Q/10TC60usgIsA8EU2s99MqMc43K7cUHfbTJX"
    "8OBr4ydDPEouLNaxxbeLGzXYPoX9Ye3fZfjhSMbH/NGPx4moEZBpuG7URIhK+RWKVeRE6LVCjIUo"
    "Le8jRULS0E25UHYOR1gRkHD2VIKOQbWA5PiWIZ6/P7FZyV2uCLuwj62efmDd1W7sNm66B7bAljh6"
    "vPTcHNEtB7RsdDoAEubylXkWWZSZLwhVhOYz3yCqqyXuXidyYalgqLYE9WAg/J2vCsEOX16g9tps"
    "rqxv/p7DSkquhgRdKt0c9mVdZYGlgYluhoQFdppvpUm3v0rpiL5adC3cpLNIwcBr3eRZJRDMiepq"
    "RdYJFzpJ6Bqp7ogd7/cb7JGuUY7Dle4EngP0K3VHv1WzlTNskzxehPo+SHqMW3nvnm87RKarlJVS"
    "nyRHFEkiy2ZZp7cJ28teCrHmC7stkNwo8UfRVvJ7fNIDhlO3edX53qajCxTJ/U9D0UrIxMTjF/SW"
    "XnCN68zf+rdJvZCFq7o3OPFiG2OPc2TDKBttu6857ZvhadXn9cC7NN0bnwEhh14j/fwpYKnZZFoA"
    "goyZck5IFU9NgEI5zCTJf8fnqnpIxxTetILRFAQqqFEWOQgLAkQaiCAVNVF5FUIFJnWQBb8FBLCj"
    "NzLUT5SxHvDCjfzHqKLl4MjPWcjZAasZCAmC6KGfRJGuQdau9qcr7nXmB3sQau9KfxssGI+BDO1F"
    "jrE5Fag=")
KDB_KEYFILE = base64.b64decode(
    "Z5Pm1ydQVk+t5yc+5enYax415SV5gkaC+0H+S3pckOV+uLL27qJEk7Xg+wZp9cJKdKvsVwYlMNfm"
    "Gfaaw9aWzpRA/awLcB7P03RoIJeSHtlxpVRGyJC7cmKyrsDy0Wj0ZquqqA==")
