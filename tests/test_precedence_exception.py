"""Tests that measure the reach of the source-neutral precedence exception.

`.claude/rules/external-apis.md` states that `python/test/testdata/` decides where it and
another FoxIO source both hold a value for one method on one connection. #332 added one
exception for the Zeek baseline alone, and #334 makes it source-neutral: where
`tests/foxio_deviations.json` declines the FoxIO Python value under a decided entry, any
other FoxIO implementation may hold the reference value for that method on that
connection.

The exception reads facts from the register and the vectors. It reads no judgment about
which value looks right.

1. The key is the value form, and the FoxIO Python expected-output file holds a value at
   that connection, that method and that occurrence. The occurrence form records a stream
   the Python file omits, and the Rust snapshot rule already decides that case.
2. The entry carries `decided`, so a recorded decision names the issue. An undecided
   entry is an open question, and this exception does not reach it.
3. The entry carries `capability: false`, so the decline records a disagreement about the
   value. A decline that records a capability this project chose not to build bars the
   row, because no implementation change could ever close the difference. #334 held this
   fact as a set of issue numbers in this file, and #341 moved it into the register.
   `tests/foxio_deviations.py` states the field, and `tests/test_foxio_deviations.py`
   requires it on every decided entry.
4. Another FoxIO source holds a value for the same method, the same connection and the
   same occurrence.
5. The remaining sources hold one value between them. Where they hold different values,
   no source holds the reference and the row stays declined.

**Fact 1 reads the vectors, which this repository holds, so a register change alone
cannot move it.** `gre-erspan-vxlan.pcap/0:65174/JA4T.1` proves the fact carries weight:
the key is the value form, the FoxIO Python file holds no JA4T value, and #215 declines
the FoxIO Rust value rather than a Python one.

**Facts 4 and 5 read `SOURCE_VALUES`, which the run of #334 measured against the pinned
FoxIO checkout.** The measurement read all 135 register keys against 38 Rust snapshots,
37 Wireshark testdata files and 7 Zeek baselines at commit
`27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`. It attributed every Wireshark value to a
connection by resolving `frame.number` against the capture, because the Wireshark
testdata records a frame number and no connection.

**#334 left the 35 source values of #129 out of the table, and #347 put them in.** The
exclusion enforced the capability bar a second time. A wrong reading of the field then
moved nothing, and no case failed. The table now holds every measured row, and the field
alone bars the 35. `test_the_field_alone_bars_the_measured_capability_rows` reads the
reach with the field flipped. #347 measured the 35 rows against the same pinned commit
and by the same method.

These cases read the register, the vectors and prose. They import nothing from `ja4plus`
and they produce no fingerprint.
"""

import json
import re
from pathlib import Path

import pytest

from tests.conformance_index import index_expected
from tests.foxio_deviations import REGISTER_PATH, load_register

REPO_ROOT = Path(__file__).resolve().parent.parent

VECTORS = REPO_ROOT / "tests" / "foxio_vectors"

RULE_PAGE = REPO_ROOT / ".claude" / "rules" / "external-apis.md"

ZEEK_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "zeek.md"

JA4SSH_PAGE = REPO_ROOT / "docs" / "specs" / "foxio" / "JA4SSH.md"

# The value every other FoxIO source holds for one register key, keyed by the register
# key. The run of #334 measured 23 rows, and the run of #347 measured the 35 rows of
# #129. The table holds every decided value-form key that a source covers. The capability
# field is the one fact that bars the 35.
SOURCE_VALUES = {
    "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-C.1": {
        "rust": "113_64",
        "wireshark": "264_0_quic",
        "zeek": "113_64_q",
    },
    "chrome-cloudflare-quic-with-secrets.pcapng/0:50280/JA4L-S.1": {
        "rust": "9285_56",
        "wireshark": "9285_0_quic",
        "zeek": "10990_56_q",
    },
    "chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H.1": {
        "rust": "ge20nn16enus_0f5a7a41a252_000000000000_000000000000",
        "wireshark": "ge20nn12enus_60f823d07c94_000000000000_000000000000",
    },
    "chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro.1": {
        "wireshark": "ge20nn12enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language__",
    },
    "gre-erspan-vxlan.pcap/0:65174/JA4T.1": {
        "rust": "8192__0_0",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.1": {
        "rust": "ge20cn23enus_641f0b6ae3f0_c7713052b7e4_348cad68b6fb",
        "wireshark": "ge20cn19enus_cb83bf27b7a9_c7713052b7e4_348cad68b6fb",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.10": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.11": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.12": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.13": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.14": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.15": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.2": {
        "rust": "ge20cn17enus_949f364da66f_e43af2e8abfe_015bb0ca5596",
        "wireshark": "ge20cn13enus_8e33b43baae9_e43af2e8abfe_015bb0ca5596",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.3": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.4": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.5": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.6": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.7": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.8": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H.9": {
        "rust": "ge20cr22enus_265608141a12_10ff48fdaa11_ac323afc21f7",
        "wireshark": "ge20cr18enus_40430d236f7c_10ff48fdaa11_ac323afc21f7",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.1": {
        "wireshark": "ge20cn19enus_sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-ch-ua-arch,sec-ch-ua-platform-version,sec-ch-ua-model,sec-ch-ua-bitness,sec-ch-ua-wow64,sec-ch-ua-full-version-list,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PSIDCC=APoG2W80ReNqY71qp2I8hZk8BsmVmWk_ejh3LtS-HuboNyHI73aZAnaQhqTWkTHUiz45rCPv,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.10": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.11": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.12": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.13": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.14": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.15": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.2": {
        "wireshark": "ge20cn13enus_upgrade-insecure-requests,user-agent,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,SIDCC=APoG2W9RK6clrsnkAMIVg0rYm3am1HkEfg8dAPun6iMCVEt_0tkuDFLdjjiADNirDnahrwzeAQ,__Secure-1PSIDCC=APoG2W81CyAxqg4qdIqnAV5zkvXLzRfSMgA4mkydeWg9IeL-6814d1G7t95sNNSRTqgzkZji,__Secure-3PSIDCC=APoG2W_WfImJeKcVAH4O7muEBxWxwaZd-WwKWyO1PfcqO-vHYfyX0O9GCzXU0t6LNlvXg9w7,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.3": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.4": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.5": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.6": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.7": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.8": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.9": {
        "wireshark": "ge20cr18enus_sec-ch-ua,sec-ch-ua-mobile,user-agent,sec-ch-ua-arch,sec-ch-ua-full-version,sec-ch-ua-platform-version,sec-ch-ua-full-version-list,sec-ch-ua-bitness,sec-ch-ua-model,sec-ch-ua-wow64,sec-ch-ua-platform,accept,x-client-data,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language_VISITOR_INFO1_LIVE,LOGIN_INFO,SID,__Secure-1PSIDTS,__Secure-3PSIDTS,__Secure-1PSID,__Secure-3PSID,HSID,SSID,APISID,SAPISID,__Secure-1PAPISID,__Secure-3PAPISID,YSC,VISITOR_PRIVACY_METADATA,SIDCC,__Secure-1PSIDCC,__Secure-3PSIDCC_VISITOR_INFO1_LIVE=5CuVaSL9wDE,LOGIN_INFO=AFmmF2swRgIhAOltLQJUxXKDwpOeYd1REmFWIv-SZOX5_Mt3l8dB8TUyAiEAq9Hxidx9TIYr9Usi0QvZwoAY7hWdD0TrwUBJ-vDNhFw:QUQ3MjNmeHlXOVFoOGc1bWNjT2VKNnZPVlJzVktiM3pXc2ExNENfTkFqZzh6SEFIODBCWUo2d0hZU1preThtcjVjNW1oV1NXX2dXbV9laUsxN2gxNlRMZGM4QlVEMkJNVFR3UWpfbWtoSTdXSlVYUnRIekJiVmxXT0NLMklXRmxDSEZ1M2xDYkZjYld5NTg2azdMOTRuSFg0SEQ1NmhCcXJR,SID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3oyvm4YN6azbdj99oAEv6g.,__Secure-1PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-3PSIDTS=sidts-CjEB3e41hfRDIv3qE6IhIGL4regkBrZQzMepIsMI60XzPXMHjuDBFb8Jzi6e3Q_XguntEAA,__Secure-1PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK3ZH4QQAFpOKIred2Wu8QgA.,__Secure-3PSID=bAiSGpEASIdYDutJlWaOLSpT-A0OtSymfAqQHglc8wCyKvJK9erTPZ3XpDCPS4p8f5PnjQ.,HSID=AOF5tyazl7ZAKFyZY,SSID=AqFHwVpJHIK9H1lfZ,APISID=pEXHoyISD5STpHG9/AajENhWjLXnfNmbhI,SAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-1PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,__Secure-3PAPISID=_4e9wsQoZw81B655/A2zwmxsRQhzaXtNW0,YSC=fmJvKZ98ZzM,VISITOR_PRIVACY_METADATA=CgJDQRICGgA%3D,SIDCC=APoG2W_-Qsh5iRlLVDzN2OkIW0cAz_0yN7-rr-KCkBL1IXxKRG0CdQP6-ZkTxzy7D4H-DselDw,__Secure-1PSIDCC=APoG2W-ysomredm6Llr5hD-_lAbJvmQ7uTdjhZQS5pPUXf4Avu9tKLhKjZXAlGhtseKPB6dC,__Secure-3PSIDCC=APoG2W-TOlRHTYrgLGQiaBdvBhHjJ9JVpf6IZAguDfwj958a7ObWfITcu9ql2EdL0cxQ_e33,",
    },
    "http2-with-cookies.pcapng/0:58847/JA4X.1": {
        "rust": "a373a9f83c6b_7022c563de38_2e3757343cb0",
        "wireshark": "a373a9f83c6b_7022c563de38_2e3757343cb0",
    },
    "http2-with-cookies.pcapng/0:58847/JA4X.2": {
        "rust": "a373a9f83c6b_a373a9f83c6b_5d71497f7704",
        "wireshark": "a373a9f83c6b_a373a9f83c6b_5d71497f7704",
    },
    "http2-with-cookies.pcapng/0:58847/JA4X.3": {
        "rust": "7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b",
        "wireshark": "7d5dbb3783b4_a373a9f83c6b_2fbee3f04f3b",
    },
    "ssh-r.pcap/0:64980/JA4SSH.2": {
        "rust": "c64s64_c33s48_c42s2",
        "wireshark": "c64s64_c33s48_c41s2",
    },
    "ssh-r.pcap/1:46394/JA4SSH.1": {
        "rust": "c48s21_c7s5_c5s5",
        "wireshark": "c48s21_c6s5_c4s5",
    },
    "ssh-r.pcap/2:46396/JA4SSH.1": {
        "rust": "c76s76_c104s96_c19s82",
        "wireshark": "c76s76_c104s96_c19s82",
    },
    "ssh-scp-1050.pcap/0:49237/JA4SSH.3": {
        "rust": "c0s1460_c0s200_c36s0",
        "wireshark": "c0s1460_c0s200_c36s0",
    },
    "ssh-scp-1050.pcap/0:49237/JA4SSH.4": {
        "rust": "c0s1460_c0s200_c23s0",
        "wireshark": "c0s1460_c0s200_c23s0",
    },
    "ssh2.pcapng/14:57377/JA4SSH.2": {
        "rust": "c36s52_c42s76_c51s2",
        "zeek": "c36s52_c42s76_c51s2",
    },
    "ssh2.pcapng/33:51810/JA4L-S.1": {
        "wireshark": "16192_57_quic",
    },
    "ssh2.pcapng/36:61861/JA4L-C.1": {
        "rust": "169_128",
        "wireshark": "169_128_quic",
    },
    "ssh2.pcapng/36:61861/JA4L-S.1": {
        "rust": "5389_57",
        "wireshark": "5389_57_quic",
    },
    "tls3.pcapng/21:62481/JA4L-C.1": {
        "rust": "59_128",
        "wireshark": "90_128_quic",
        "zeek": "60_128_q",
    },
    "tls3.pcapng/21:62481/JA4L-S.1": {
        "rust": "4213_59",
        "wireshark": "4213_59_quic",
        "zeek": "4214_59_q",
    },
    "tls3.pcapng/22:61732/JA4L-C.1": {
        "rust": "336_128",
        "wireshark": "336_128_quic",
        "zeek": "336_128_q",
    },
    "tls3.pcapng/22:61732/JA4L-S.1": {
        "rust": "5580_57",
        "wireshark": "5580_57_quic",
        "zeek": "5580_57_q",
    },
    "tls3.pcapng/23:49791/JA4L-C.1": {
        "rust": "40_128",
        "wireshark": "101_128_quic",
        "zeek": "40_128_q",
    },
    "tls3.pcapng/23:49791/JA4L-S.1": {
        "rust": "4455_58",
        "wireshark": "4455_58_quic",
        "zeek": "4455_58_q",
    },
    "tls3.pcapng/24:56684/JA4L-C.1": {
        "rust": "59_128",
        "wireshark": "81_128_quic",
        "zeek": "59_128_q",
    },
    "tls3.pcapng/24:56684/JA4L-S.1": {
        "rust": "3590_57",
        "wireshark": "3590_57_quic",
        "zeek": "3590_57_q",
    },
    "tls3.pcapng/25:61884/JA4L-S.1": {
        "wireshark": "3051_57_quic",
        "zeek": "3583_57_q",
    },
    "tls3.pcapng/28:58117/JA4L-C.1": {
        "rust": "45_128",
        "wireshark": "83_128_quic",
        "zeek": "45_128_q",
    },
    "tls3.pcapng/28:58117/JA4L-S.1": {
        "rust": "3298_58",
        "wireshark": "3298_58_quic",
        "zeek": "3298_58_q",
    },
}

# The count of decided value-form keys the capability bar holds out. 58 of the 76 decided
# value-form keys carry a source value, and 35 of the 58 are these.
CAPABILITY_VALUE_KEYS = 37

# The count of measured rows the capability bar holds out. The run of #347 read all 37
# rows of #129 and found a source value for 35. The other two are the JA4X keys of
# `chrome-cloudflare-quic-with-secrets.pcapng`. No Rust snapshot and no Wireshark file
# holds a JA4X value for that capture, so the table records neither key.
CAPABILITY_ROWS_MEASURED = 35

# The methods no Zeek baseline holds a reference value for. Three rules of the Zeek script
# part it from the Python reference, and the bar stands above the exception.
BARRED_METHODS = {"JA4L-C", "JA4L-S"}

# The name of the Zeek source, which `BARRED_METHODS` bars.
ZEEK = "zeek"

# The name of the Wireshark source.
WIRESHARK = "wireshark"

# The issue every capability decline names. All 43 capability entries carry it.
CAPABILITY_ISSUE = 129

# The measured #129 rows that the `capability` field alone holds out of the reach. Each
# row carries a source value that the remaining sources agree on, so the field is the one
# fact that bars it. The 16 JA4H rows are absent here. Each one carries a Rust value that
# differs from the Wireshark value, so the disagreement bar holds it out as well.
CAPABILITY_ROWS_THE_FIELD_ALONE_BARS = {
    "chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro.1",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.1",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.10",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.11",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.12",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.13",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.14",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.15",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.2",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.3",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.4",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.5",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.6",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.7",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.8",
    "http2-with-cookies.pcapng/0:58847/JA4H_ro.9",
    "http2-with-cookies.pcapng/0:58847/JA4X.1",
    "http2-with-cookies.pcapng/0:58847/JA4X.2",
    "http2-with-cookies.pcapng/0:58847/JA4X.3",
}

# The rows the exception reaches. `.claude/rules/external-apis.md` states the rule, and
# each row carries a recorded decline that names an issue.
REACHED_KEYS = {
    "ssh-r.pcap/2:46396/JA4SSH.1",
    "ssh-scp-1050.pcap/0:49237/JA4SSH.3",
    "ssh-scp-1050.pcap/0:49237/JA4SSH.4",
    "ssh2.pcapng/14:57377/JA4SSH.2",
    "ssh2.pcapng/33:51810/JA4L-S.1",
    "tls3.pcapng/25:61884/JA4L-S.1",
}

# The two rows the Wireshark dissector alone reaches, both under #225. The dissector
# appends a third part to every JA4L and JA4LS value it writes, which is the second of the
# three rules that bar a Zeek JA4L value. #334 reports the finding, and the user decides
# whether the bar reaches the dissector. A bar that reached it would remove these two rows.
DISSECTOR_ONLY_JA4L_KEYS = {
    "ssh2.pcapng/33:51810/JA4L-S.1",
    "tls3.pcapng/25:61884/JA4L-S.1",
}

# The baseline that holds the reference value for the one row a Zeek baseline reaches.
SSH2_BASELINE = "Scripts.ja4-ssh2/ja4ssh.log"


# The sentence of `.claude/rules/external-apis.md` that states the reach and the register
# key count. The key count went stale when #272 removed an entry, because no case measured
# it. #380 states the sentence as a condition the cases below test.
EXCEPTION_REACH_COUNTS = re.compile(
    r"The exception reaches (\d+) rows? of the (\d+) the register holds"
)


def stated_exception_reach_counts(document):
    """Return the two counts the rule states for the reach of the exception.

    Args:
        document: The text of `.claude/rules/external-apis.md`, flattened.

    Returns:
        The stated count of rows the exception reaches, then the stated count of register
        keys.

    Raises:
        ValueError: The document states the two counts on no sentence, or on more than one
            sentence.
    """
    matches = EXCEPTION_REACH_COUNTS.findall(document)
    if len(matches) != 1:
        raise ValueError(
            "the rule states the reach counts on {} sentences, and it states them on one".format(
                len(matches)
            )
        )
    return int(matches[0][0]), int(matches[0][1])


def flatten(path):
    """Return the text of one page with every run of whitespace as one space.

    A Markdown page wraps a sentence across lines, so a search for a phrase fails on the
    line break rather than on the missing phrase.

    Args:
        path: The path of one page.

    Returns:
        The text of the page on one line.
    """
    return " ".join(path.read_text().split())


def split_key(key):
    """Return the parts of one value-form register key, or None.

    Args:
        key: One register key.

    Returns:
        A (capture, stream index, source port, method, occurrence) tuple, or None where
        the key carries the occurrence form.
    """
    parts = key.split("/")
    if len(parts) != 3:
        return None
    capture, connection, tail = parts
    method, _, occurrence = tail.rpartition(".")
    index, _, port = connection.partition(":")
    if not method or not occurrence.isdigit():
        return None
    return capture, index, port, method, int(occurrence)


def python_value(key):
    """Return the FoxIO Python value one register key names, or None.

    The exception rests on a declined Python value, so a key the Python file holds no
    value for declines nothing and the exception passes over it.

    Args:
        key: One register key.

    Returns:
        The value the FoxIO expected-output file holds, or None where the file holds no
        value for that connection, that method and that occurrence.
    """
    parts = split_key(key)
    if parts is None:
        return None
    capture, index, port, method, occurrence = parts
    path = VECTORS / "{}.json".format(capture)
    if not path.exists():
        return None
    with open(path) as handle:
        streams = index_expected(json.load(handle))
    for stream in streams.values():
        if str(stream.index) == index and stream.src_port == port:
            return stream.methods.get(method, {}).get(occurrence)
    return None


def remaining_sources(key, method):
    """Return the sources that may hold the reference value for one row.

    Args:
        key: One register key.
        method: The method the key names.

    Returns:
        A map of source name to value. The map drops a Zeek JA4L or JA4LS value, because
        the bar on that value stands above the exception.
    """
    held = SOURCE_VALUES.get(key, {})
    if method in BARRED_METHODS:
        return {name: value for name, value in held.items() if name != ZEEK}
    return dict(held)


def exception_reach(register):
    """Return every register key the source-neutral precedence exception reaches.

    Args:
        register: The register that `load_register` returns.

    Returns:
        The set of keys where the register declines the FoxIO Python value under a
        decided entry that records a disagreement about the value, and the remaining
        FoxIO sources hold one value between them.
    """
    reach = set()
    for key, deviation in register.items():
        parts = split_key(key)
        if parts is None:
            continue
        if not deviation.decided:
            continue
        if deviation.capability:
            continue
        if python_value(key) is None:
            continue
        sources = remaining_sources(key, parts[3])
        if not sources:
            continue
        if len(set(sources.values())) != 1:
            continue
        reach.add(key)
    return reach


class TestTheReachOfTheException:
    """The exception reaches the rows the rule names, and no other row."""

    def test_the_exception_reaches_six_register_keys(self):
        assert exception_reach(load_register()) == REACHED_KEYS

    def test_the_rule_names_every_row_the_exception_reaches(self):
        page = RULE_PAGE.read_text()
        for key in sorted(exception_reach(load_register())):
            assert key in page, "{} names no row for {}".format(RULE_PAGE, key)

    def test_every_measured_row_names_a_decided_register_key(self):
        register = load_register()
        for key in SOURCE_VALUES:
            assert key in register, "{} names no register entry".format(key)
            assert register[key].decided, "{} names an undecided entry".format(key)

    def test_every_measured_capability_row_names_the_issue_the_bar_exists_for(self):
        """A measured row the field bars names #129, and the table holds 35 of them.

        #334 measured these 35 rows and left them out, and
        `test_no_measured_row_records_a_capability_decline` asserted the exclusion.
        #347 removed the exclusion, and this case replaces it. A capability decline that
        names another issue reaches a bar no measurement has read. This case fails on
        such a row, and a reader then decides whether the bar still holds.
        """
        register = load_register()
        barred = {key for key in SOURCE_VALUES if register[key].capability}
        assert len(barred) == CAPABILITY_ROWS_MEASURED
        for key in barred:
            assert register[key].issue == CAPABILITY_ISSUE, (
                "{} records a capability decline under #{}".format(key, register[key].issue)
            )


class TestTheBarsOnTheException:
    """Each bar holds out the rows the decision names."""

    def test_the_exception_passes_over_a_capability_decline(self):
        register = load_register()
        capability = {key for key, entry in register.items() if entry.capability}
        assert capability, "the register records no capability decline"
        assert not capability & exception_reach(register)

    def test_the_capability_bar_holds_out_thirty_seven_value_form_keys(self):
        register = load_register()
        held = {
            key
            for key, entry in register.items()
            if split_key(key) is not None and entry.decided and entry.capability
        }
        assert len(held) == CAPABILITY_VALUE_KEYS

    def test_the_bar_reads_the_field_and_not_the_issue_number(self, tmp_path):
        """The register records the kind, so a new capability decline needs no test edit.

        The row is a #96 value decline the exception reaches. The copy records a
        capability decline against the same issue and the same cause, and the exception
        passes over it. #341 built the field for this reason, and this case is the proof
        that the field carries the bar.
        """
        key = "ssh-r.pcap/2:46396/JA4SSH.1"
        with open(REGISTER_PATH) as handle:
            entry = json.load(handle)[key]
        path = tmp_path / "register.json"
        path.write_text(json.dumps({key: dict(entry, capability=False)}))
        assert exception_reach(load_register(path)) == {key}
        path.write_text(json.dumps({key: dict(entry, capability=True)}))
        assert exception_reach(load_register(path)) == set()

    def test_the_field_alone_bars_the_measured_capability_rows(self, tmp_path):
        """The reach rises when the `capability` field reads false on the #129 entries.

        #334 measured the 35 #129 source values and left them out of `SOURCE_VALUES`.
        No case could then measure what the field does on the issue the bar exists for.
        #347 put them in the table, and this case flips the field on every #129 entry
        and reads the reach again. The rise proves the field carries the bar alone.
        """
        with open(REGISTER_PATH) as handle:
            register = json.load(handle)
        assert exception_reach(load_register()) == REACHED_KEYS
        flipped = {
            key: dict(entry, capability=False) if entry.get("issue") == CAPABILITY_ISSUE else entry
            for key, entry in register.items()
        }
        path = tmp_path / "register.json"
        path.write_text(json.dumps(flipped))
        assert exception_reach(load_register(path)) == (
            REACHED_KEYS | CAPABILITY_ROWS_THE_FIELD_ALONE_BARS
        )

    def test_the_exception_passes_over_a_row_whose_sources_disagree(self):
        register = load_register()
        reach = exception_reach(register)
        for key, held in SOURCE_VALUES.items():
            sources = remaining_sources(key, split_key(key)[3])
            if len(set(sources.values())) > 1:
                assert key not in reach, "{} holds {} and stays declined".format(key, sources)

    def test_the_exception_passes_over_a_row_the_python_file_holds_no_value_for(self):
        key = "gre-erspan-vxlan.pcap/0:65174/JA4T.1"
        register = load_register()
        assert key in register, "{} names no register entry".format(key)
        assert register[key].decided
        assert SOURCE_VALUES[key], "{} names no source value".format(key)
        assert python_value(key) is None
        assert key not in exception_reach(register)

    def test_the_exception_passes_over_a_zeek_ja4l_value(self):
        key = "tls3.pcapng/22:61732/JA4L-S.1"
        assert ZEEK in SOURCE_VALUES[key]
        assert ZEEK not in remaining_sources(key, "JA4L-S")

    def test_the_exception_passes_over_an_undecided_entry(self, tmp_path):
        path = tmp_path / "register.json"
        path.write_text(
            json.dumps(
                {
                    "ssh2.pcapng/14:57377/JA4SSH.2": {
                        "issue": 999,
                        "cause": "#999 decides whether ja4plus reads the second window.",
                    }
                }
            )
        )
        assert exception_reach(load_register(path)) == set()

    def test_the_exception_passes_over_the_occurrence_form(self):
        register = load_register()
        for key in exception_reach(register):
            assert split_key(key) is not None


class TestTheThirdPartFinding:
    """The Wireshark dissector writes the third part the Zeek bar names."""

    def test_the_dissector_writes_a_third_part_on_every_ja4l_value_the_table_holds(self):
        for key, held in SOURCE_VALUES.items():
            if split_key(key)[3] not in BARRED_METHODS:
                continue
            value = held.get(WIRESHARK)
            if value is None:
                continue
            assert value.count("_") == 2, "{} holds {} with no third part".format(key, value)

    def test_a_bar_that_reached_the_dissector_would_remove_two_rows(self):
        reach = exception_reach(load_register())
        assert DISSECTOR_ONLY_JA4L_KEYS <= reach
        for key in DISSECTOR_ONLY_JA4L_KEYS:
            assert set(remaining_sources(key, split_key(key)[3])) == {WIRESHARK}
        assert len(reach - DISSECTOR_ONLY_JA4L_KEYS) == 4


class TestThePagesThatCarryTheRule:
    """Each page that states the rule cites it, and the rule states both bars."""

    def test_the_rule_states_the_source_neutral_exception(self):
        assert "any other FoxIO implementation may hold the reference value" in flatten(RULE_PAGE)

    def test_the_rule_states_the_capability_bar(self):
        assert "A capability decline bars the row" in flatten(RULE_PAGE)

    def test_the_rule_states_the_disagreement_bar(self):
        page = flatten(RULE_PAGE)
        assert "no source holds the reference and the row stays declined" in page

    def test_the_rule_names_the_check_that_measures_the_reach(self):
        assert "tests/test_precedence_exception.py" in flatten(RULE_PAGE)

    def test_the_ja4ssh_page_cites_the_rule_that_licenses_its_reading(self):
        page = flatten(JA4SSH_PAGE)
        assert "ssh2.pcapng/14:57377/JA4SSH.2" in page
        assert "A declined FoxIO Python value forfeits its precedence" in page

    def test_the_rule_states_the_reach_the_register_holds(self):
        assert stated_exception_reach_counts(flatten(RULE_PAGE))[0] == len(
            exception_reach(load_register())
        )

    def test_the_rule_states_the_register_key_count_the_register_holds(self):
        assert stated_exception_reach_counts(flatten(RULE_PAGE))[1] == len(load_register())

    def test_the_reader_rejects_a_document_that_states_the_counts_nowhere(self):
        with pytest.raises(ValueError, match="0 sentences"):
            stated_exception_reach_counts("The exception reaches the rows the rule names.")

    def test_the_reader_rejects_a_document_that_states_the_counts_twice(self):
        document = (
            "The exception reaches 1 row of the 2 the register holds."
            " The exception reaches 3 rows of the 4 the register holds."
        )
        with pytest.raises(ValueError, match="2 sentences"):
            stated_exception_reach_counts(document)

    def test_the_reader_reads_the_two_counts_the_sentence_states(self):
        document = "The exception reaches 6 rows of the 134 the register holds."
        assert stated_exception_reach_counts(document) == (6, 134)

    def test_the_zeek_page_rates_the_baseline_the_exception_reaches(self):
        rows = [line for line in ZEEK_PAGE.read_text().splitlines() if SSH2_BASELINE in line]
        assert rows, "{} holds no rating row for {}".format(ZEEK_PAGE, SSH2_BASELINE)
        for row in rows:
            assert "Undecided" not in row, "{} rates {} as undecided".format(
                ZEEK_PAGE, SSH2_BASELINE
            )
