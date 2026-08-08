# The mutation sweep

`tests/mutation_sweep.py` writes this page. Never edit it by hand.

The sweep asks of every case: would this fail if the code were wrong? It changes
one expression in one module, runs the suite, and records which cases fail.
A case that no mutation makes fail is a candidate, and a candidate needs a reader.
A case may be correct and the mutation wrong.

Read the candidate list with two limits in mind.

1. A case that the baseline reports as skipped or as xfailed cannot fail, so it
   reaches this list for a reason the suite already states.
2. A sample of the mutations of a module answers for that sample alone. To settle
   one case, sweep the module whole against the file that holds the case:
   `--max-per-module 0 --tests tests/<file>.py`.

| Field | Value |
|---|---|
| Date | 2026-08-07T23:09:48 |
| Cases collected | 2857 |
| Mutations per module | 12 |
| Sampling seed | 0 |
| Tests | `tests/` |
| Seconds | 3577.2 |
| Candidates | 976 |

## What the sweep applied to each module

| Module | Mutations | Killed | Survived | Unusable |
|---|---|---|---|---|
| `ja4plus/__init__.py` | 4 | 1 | 3 | 0 |
| `ja4plus/cli.py` | 12 | 2 | 10 | 0 |
| `ja4plus/collector.py` | 12 | 0 | 12 | 0 |
| `ja4plus/ja4db.py` | 12 | 2 | 10 | 0 |
| `ja4plus/processor.py` | 12 | 9 | 3 | 0 |
| `ja4plus/fingerprinters/__init__.py` | 9 | 0 | 9 | 0 |
| `ja4plus/fingerprinters/base.py` | 2 | 1 | 1 | 0 |
| `ja4plus/fingerprinters/ja4.py` | 12 | 9 | 3 | 0 |
| `ja4plus/fingerprinters/ja4d.py` | 12 | 9 | 3 | 0 |
| `ja4plus/fingerprinters/ja4d6.py` | 12 | 9 | 3 | 0 |
| `ja4plus/fingerprinters/ja4h.py` | 12 | 7 | 5 | 0 |
| `ja4plus/fingerprinters/ja4l.py` | 12 | 7 | 5 | 0 |
| `ja4plus/fingerprinters/ja4s.py` | 12 | 6 | 6 | 0 |
| `ja4plus/fingerprinters/ja4ssh.py` | 12 | 6 | 6 | 0 |
| `ja4plus/fingerprinters/ja4t.py` | 12 | 12 | 0 | 0 |
| `ja4plus/fingerprinters/ja4ts.py` | 12 | 10 | 2 | 0 |
| `ja4plus/fingerprinters/ja4x.py` | 12 | 11 | 1 | 0 |
| `ja4plus/utils/__init__.py` | 0 | 0 | 0 | 0 |
| `ja4plus/utils/http_utils.py` | 12 | 8 | 4 | 0 |
| `ja4plus/utils/loopback.py` | 5 | 3 | 2 | 0 |
| `ja4plus/utils/packet_utils.py` | 12 | 9 | 3 | 0 |
| `ja4plus/utils/quic_utils.py` | 12 | 7 | 5 | 0 |
| `ja4plus/utils/ssh_utils.py` | 12 | 5 | 7 | 0 |
| `ja4plus/utils/tcp_stream.py` | 12 | 11 | 1 | 0 |
| `ja4plus/utils/tls_utils.py` | 12 | 9 | 3 | 0 |
| `ja4plus/utils/tunnels.py` | 3 | 2 | 1 | 0 |
| `ja4plus/utils/x509_utils.py` | 12 | 1 | 11 | 0 |

## Every mutation

### `ja4plus/__init__.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 74 | string | `"ascii"` | `'ascii_mutated'` | killed | 1 |
| 84 | string | `"0.6.0"` | `'0.6.0_mutated'` | survived | 0 |
| 85 | string | `"ja4plus contributors"` | `'ja4plus contributors_mutated'` | survived | 0 |
| 86 | string | `"BSD-3-Clause"` | `'BSD-3-Clause_mutated'` | survived | 0 |

### `ja4plus/cli.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 43 | string | `"ja4"` | `'ja4_mutated'` | killed | 1 |
| 206 | string | `"last_raw"` | `'last_raw_mutated'` | survived | 0 |
| 222 | number | `1` | `2` | survived | 0 |
| 246 | compare | `==` | `!=` | survived | 0 |
| 262 | string | `"last_raw"` | `'last_raw_mutated'` | survived | 0 |
| 280 | string | `"\nCapture stopped."` | `'\nCapture stopped._mutated'` | survived | 0 |
| 298 | number | `1` | `2` | survived | 0 |
| 331 | number | `90` | `91` | survived | 0 |
| 332 | string | `"csv"` | `'csv_mutated'` | survived | 0 |
| 347 | string | `"info"` | `'info_mutated'` | survived | 0 |
| 441 | string | `"--force"` | `'--force_mutated'` | survived | 0 |
| 447 | string | `"analyze"` | `'analyze_mutated'` | killed | 7 |

### `ja4plus/collector.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 37 | number | `0` | `1` | survived | 0 |
| 81 | string | `"ja4h"` | `'ja4h_mutated'` | survived | 0 |
| 110 | boolop | `and` | `or` | survived | 0 |
| 110 | compare | `>=` | `>` | survived | 0 |
| 116 | string | `"@timestamp"` | `'@timestamp_mutated'` | survived | 0 |
| 139 | string | `"ip"` | `'ip_mutated'` | survived | 0 |
| 143 | string | `"destination"` | `'destination_mutated'` | survived | 0 |
| 173 | string | `"interface"` | `'interface_mutated'` | survived | 0 |
| 186 | boolop | `and` | `or` | survived | 0 |
| 191 | boolop | `and` | `or` | survived | 0 |
| 197 | string | `' with filter '` | `"' with filter '_mutated"` | survived | 0 |
| 210 | string | `"Interrupted by user\n"` | `'Interrupted by user\n_mutated'` | survived | 0 |

### `ja4plus/ja4db.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 22 | string | `"ja4plus-mapping.csv"` | `'ja4plus-mapping.csv_mutated'` | killed | 6 |
| 50 | string | `"ja4x"` | `'ja4x_mutated'` | survived | 0 |
| 50 | string | `"ja4tscan"` | `'ja4tscan_mutated'` | survived | 0 |
| 51 | string | `""` | `'_mutated'` | survived | 0 |
| 56 | string | `"notes"` | `'notes_mutated'` | survived | 0 |
| 92 | compare | `in` | `not in` | killed | 6 |
| 112 | number | `5` | `6` | survived | 0 |
| 113 | string | `"Accept"` | `'Accept_mutated'` | survived | 0 |
| 115 | compare | `==` | `!=` | survived | 0 |
| 117 | boolop | `and` | `or` | survived | 0 |
| 119 | string | `"application"` | `'application_mutated'` | survived | 0 |
| 119 | string | `"application"` | `'application_mutated'` | survived | 0 |

### `ja4plus/processor.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 47 | string | `"ja4h"` | `'ja4h_mutated'` | killed | 5 |
| 88 | string | `"type"` | `'type_mutated'` | killed | 1 |
| 90 | string | `"raw"` | `'raw_mutated'` | killed | 1 |
| 90 | string | `"last_raw"` | `'last_raw_mutated'` | survived | 0 |
| 92 | string | `"src_ip"` | `'src_ip_mutated'` | killed | 1 |
| 94 | string | `"dst_ip"` | `'dst_ip_mutated'` | killed | 1 |
| 95 | string | `"dst_port"` | `'dst_port_mutated'` | killed | 1 |
| 126 | boolop | `or` | `and` | killed | 3 |
| 128 | string | `""` | `'_mutated'` | killed | 1 |
| 137 | string | `"udp"` | `'udp_mutated'` | killed | 2 |
| 141 | string | `""` | `'_mutated'` | survived | 0 |
| 143 | compare | `>` | `>=` | survived | 0 |

### `ja4plus/fingerprinters/__init__.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 16 | string | `"JA4Fingerprinter"` | `'JA4Fingerprinter_mutated'` | survived | 0 |
| 17 | string | `"JA4SFingerprinter"` | `'JA4SFingerprinter_mutated'` | survived | 0 |
| 18 | string | `"JA4HFingerprinter"` | `'JA4HFingerprinter_mutated'` | survived | 0 |
| 19 | string | `"JA4LFingerprinter"` | `'JA4LFingerprinter_mutated'` | survived | 0 |
| 20 | string | `"JA4XFingerprinter"` | `'JA4XFingerprinter_mutated'` | survived | 0 |
| 21 | string | `"JA4SSHFingerprinter"` | `'JA4SSHFingerprinter_mutated'` | survived | 0 |
| 22 | string | `"JA4TFingerprinter"` | `'JA4TFingerprinter_mutated'` | survived | 0 |
| 23 | string | `"JA4TSFingerprinter"` | `'JA4TSFingerprinter_mutated'` | survived | 0 |
| 24 | string | `"JA4DFingerprinter"` | `'JA4DFingerprinter_mutated'` | survived | 0 |

### `ja4plus/fingerprinters/base.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 30 | string | `"Subclasses must implement this method."` | `'Subclasses must implement this method._mutated'` | survived | 0 |
| 44 | string | `"fingerprint"` | `'fingerprint_mutated'` | killed | 714 |

### `ja4plus/fingerprinters/ja4.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 29 | number | `0x5A` | `91` | survived | 0 |
| 125 | number | `0x0300` | `769` | killed | 2 |
| 133 | compare | `==` | `!=` | killed | 2 |
| 156 | string | `"alpn_raw"` | `'alpn_raw_mutated'` | killed | 9 |
| 180 | number | `0x0000` | `1` | killed | 192 |
| 190 | string | `","` | `',_mutated'` | killed | 342 |
| 224 | string | `"type"` | `'type_mutated'` | killed | 361 |
| 229 | string | `"is_quic"` | `'is_quic_mutated'` | survived | 0 |
| 246 | compare | `==` | `!=` | killed | 9 |
| 247 | string | `"10"` | `'10_mutated'` | killed | 9 |
| 251 | string | `"s2"` | `'s2_mutated'` | survived | 0 |
| 276 | boolop | `or` | `and` | killed | 4 |

### `ja4plus/fingerprinters/ja4d.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 24 | string | `"reqst"` | `'reqst_mutated'` | killed | 3 |
| 38 | string | `"lqsta"` | `'lqsta_mutated'` | killed | 1 |
| 95 | binop | `+` | `-` | survived | 0 |
| 96 | compare | `<` | `<=` | survived | 0 |
| 100 | number | `240` | `241` | killed | 18 |
| 115 | compare | `==` | `!=` | killed | 18 |
| 117 | number | `0` | `1` | killed | 1 |
| 147 | string | `"has_request_ip"` | `'has_request_ip_mutated'` | killed | 19 |
| 150 | string | `"param_list"` | `'param_list_mutated'` | killed | 19 |
| 177 | string | `"msg_type"` | `'msg_type_mutated'` | killed | 19 |
| 178 | number | `9999` | `10000` | killed | 1 |
| 185 | string | `"d"` | `'d_mutated'` | survived | 0 |

### `ja4plus/fingerprinters/ja4d6.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 37 | number | `6` | `7` | killed | 1 |
| 59 | string | `"urqst"` | `'urqst_mutated'` | killed | 1 |
| 65 | number | `34` | `35` | killed | 1 |
| 78 | number | `4` | `5` | survived | 0 |
| 92 | number | `1` | `2` | killed | 1 |
| 93 | number | `3` | `4` | killed | 1 |
| 101 | binop | `+` | `-` | killed | 1 |
| 115 | number | `4` | `5` | killed | 1 |
| 133 | binop | `+` | `-` | killed | 1 |
| 133 | binop | `<<` | `>>` | survived | 0 |
| 135 | binop | `+` | `-` | survived | 0 |
| 150 | binop | `\|` | `&` | killed | 1 |

### `ja4plus/fingerprinters/ja4h.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 43 | string | `"3"` | `'3_mutated'` | survived | 0 |
| 231 | string | `"="` | `'=_mutated'` | killed | 19 |
| 246 | string | `"language"` | `'language_mutated'` | killed | 35 |
| 262 | string | `"path"` | `'path_mutated'` | survived | 0 |
| 270 | string | `""` | `'_mutated'` | survived | 0 |
| 286 | string | `""` | `'_mutated'` | survived | 0 |
| 289 | string | `"referer"` | `'referer_mutated'` | killed | 25 |
| 292 | string | `"headers"` | `'headers_mutated'` | killed | 155 |
| 302 | number | `4` | `5` | survived | 0 |
| 303 | binop | `*` | `+` | killed | 56 |
| 324 | boolop | `and` | `or` | killed | 25 |
| 378 | string | `"000000000000"` | `'000000000000_mutated'` | killed | 70 |

### `ja4plus/fingerprinters/ja4l.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 57 | number | `1.8` | `2.8` | killed | 1 |
| 253 | number | `64` | `65` | killed | 1 |
| 272 | number | `128` | `129` | survived | 0 |
| 345 | binop | `&` | `\|` | killed | 112 |
| 367 | bytes | `b"\n\n"` | `b'\n\n\x00'` | survived | 0 |
| 380 | string | `"isns"` | `'isns_mutated'` | survived | 0 |
| 402 | string | `"timestamps"` | `'timestamps_mutated'` | killed | 231 |
| 404 | string | `"timestamps"` | `'timestamps_mutated'` | killed | 82 |
| 521 | string | `"ttls"` | `'ttls_mutated'` | killed | 52 |
| 543 | string | `"D"` | `'D_mutated'` | survived | 0 |
| 550 | string | `"D"` | `'D_mutated'` | killed | 22 |
| 584 | string | `"timestamps"` | `'timestamps_mutated'` | survived | 0 |

### `ja4plus/fingerprinters/ja4s.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 90 | boolop | `or` | `and` | killed | 43 |
| 254 | binop | `+` | `-` | killed | 13 |
| 283 | number | `0` | `1` | killed | 145 |
| 287 | number | `99` | `100` | survived | 0 |
| 290 | string | `"alpn_raw"` | `'alpn_raw_mutated'` | survived | 0 |
| 293 | string | `"protocols"` | `'protocols_mutated'` | survived | 0 |
| 301 | compare | `is` | `is not` | killed | 216 |
| 380 | string | `"server_hello"` | `'server_hello_mutated'` | survived | 0 |
| 393 | number | `0x0200` | `513` | survived | 0 |
| 395 | string | `"d2"` | `'d2_mutated'` | survived | 0 |
| 410 | number | `0` | `1` | killed | 37 |
| 413 | string | `"00"` | `'00_mutated'` | killed | 169 |

### `ja4plus/fingerprinters/ja4ssh.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 142 | string | `"client_port"` | `'client_port_mutated'` | killed | 88 |
| 359 | string | `"ssh_packets"` | `'ssh_packets_mutated'` | killed | 49 |
| 421 | string | `"hassh"` | `'hassh_mutated'` | killed | 2 |
| 484 | string | `"error"` | `'error_mutated'` | killed | 4 |
| 503 | string | `"Normal interactive terminal session, client typing commands"` | `'Normal interactive terminal session, client typing commands_mutated'` | survived | 0 |
| 511 | compare | `<` | `<=` | survived | 0 |
| 515 | compare | `>` | `>=` | survived | 0 |
| 521 | string | `"description"` | `'description_mutated'` | survived | 0 |
| 557 | string | `"AWSCodeCommit (Server)"` | `'AWSCodeCommit (Server)_mutated'` | survived | 0 |
| 563 | string | `"fingerprint"` | `'fingerprint_mutated'` | survived | 0 |
| 590 | compare | `==` | `!=` | killed | 5 |
| 594 | compare | `==` | `!=` | killed | 3 |

### `ja4plus/fingerprinters/ja4t.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 56 | number | `0x02` | `3` | killed | 2 |
| 69 | compare | `==` | `!=` | killed | 32 |
| 69 | string | `"MSS"` | `'MSS_mutated'` | killed | 18 |
| 71 | number | `1` | `2` | killed | 29 |
| 72 | compare | `==` | `!=` | killed | 21 |
| 72 | string | `"NOP"` | `'NOP_mutated'` | killed | 13 |
| 74 | compare | `==` | `!=` | killed | 19 |
| 74 | string | `"WScale"` | `'WScale_mutated'` | killed | 16 |
| 79 | compare | `==` | `!=` | killed | 6 |
| 80 | string | `"8"` | `'8_mutated'` | killed | 5 |
| 82 | string | `"0"` | `'0_mutated'` | killed | 1 |
| 85 | string | `"-"` | `'-_mutated'` | killed | 17 |

### `ja4plus/fingerprinters/ja4ts.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 56 | number | `0x12` | `19` | survived | 0 |
| 70 | string | `"MSS"` | `'MSS_mutated'` | killed | 11 |
| 71 | string | `"2"` | `'2_mutated'` | killed | 13 |
| 73 | compare | `==` | `!=` | killed | 9 |
| 73 | string | `"NOP"` | `'NOP_mutated'` | killed | 9 |
| 74 | string | `"1"` | `'1_mutated'` | killed | 11 |
| 75 | string | `"WScale"` | `'WScale_mutated'` | killed | 9 |
| 76 | string | `"3"` | `'3_mutated'` | killed | 11 |
| 80 | compare | `==` | `!=` | killed | 3 |
| 82 | compare | `==` | `!=` | survived | 0 |
| 86 | string | `"-"` | `'-_mutated'` | killed | 11 |
| 86 | string | `"0"` | `'0_mutated'` | killed | 2 |

### `ja4plus/fingerprinters/ja4x.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 27 | number | `3` | `4` | killed | 77 |
| 168 | boolop | `and` | `or` | killed | 117 |
| 169 | compare | `<=` | `<` | killed | 1 |
| 218 | bool | `False` | `True` | killed | 10 |
| 222 | binop | `+` | `-` | killed | 77 |
| 222 | compare | `!=` | `==` | killed | 77 |
| 224 | number | `3` | `4` | killed | 73 |
| 226 | compare | `==` | `!=` | killed | 77 |
| 226 | number | `0` | `1` | survived | 0 |
| 231 | binop | `+` | `-` | killed | 77 |
| 336 | compare | `>` | `>=` | killed | 45 |
| 382 | string | `"subject_rdns"` | `'subject_rdns_mutated'` | killed | 60 |

### `ja4plus/utils/__init__.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| — | — | — | — | the module holds no expression to change | 0 |

### `ja4plus/utils/http_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 50 | compare | `<` | `<=` | killed | 6 |
| 96 | compare | `in` | `not in` | killed | 6 |
| 101 | string | `"="` | `'=_mutated'` | killed | 2 |
| 111 | string | `"path"` | `'path_mutated'` | killed | 1 |
| 115 | string | `"cookie_fields"` | `'cookie_fields_mutated'` | killed | 1 |
| 124 | bytes | `b"GET "` | `b'GET \x00'` | killed | 25 |
| 126 | bytes | `b"PUT "` | `b'PUT \x00'` | survived | 0 |
| 147 | string | `"ignore"` | `'ignore_mutated'` | survived | 0 |
| 151 | bool | `True` | `False` | killed | 25 |
| 170 | string | `"ignore"` | `'ignore_mutated'` | survived | 0 |
| 244 | string | `"cookies"` | `'cookies_mutated'` | survived | 0 |
| 247 | string | `"language"` | `'language_mutated'` | killed | 5 |

### `ja4plus/utils/loopback.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 23 | number | `0x18` | `25` | killed | 1 |
| 23 | number | `0x1C` | `29` | killed | 1 |
| 23 | number | `0x1E` | `31` | survived | 0 |
| 27 | bool | `False` | `True` | killed | 2 |
| 48 | bool | `True` | `False` | survived | 0 |

### `ja4plus/utils/packet_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 11 | number | `0x10` | `17` | survived | 0 |
| 36 | binop | `&` | `\|` | survived | 0 |
| 36 | boolop | `and` | `or` | killed | 8 |
| 52 | compare | `!=` | `==` | killed | 1 |
| 52 | string | `"tcp"` | `'tcp_mutated'` | killed | 1 |
| 53 | bool | `False` | `True` | survived | 0 |
| 56 | bool | `False` | `True` | killed | 1 |
| 57 | binop | `&` | `\|` | killed | 2 |
| 104 | string | `"dst"` | `'dst_mutated'` | killed | 1126 |
| 106 | string | `"dport"` | `'dport_mutated'` | killed | 1117 |
| 130 | compare | `in` | `not in` | killed | 231 |
| 132 | compare | `in` | `not in` | killed | 38 |

### `ja4plus/utils/quic_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 61 | number | `0` | `1` | killed | 76 |
| 196 | binop | `<<` | `>>` | killed | 1 |
| 257 | compare | `==` | `!=` | killed | 21 |
| 345 | string | `"!I"` | `'!I_mutated'` | survived | 0 |
| 387 | compare | `!=` | `==` | survived | 0 |
| 397 | number | `0x16` | `23` | survived | 0 |
| 426 | number | `5` | `6` | survived | 0 |
| 433 | number | `0` | `1` | killed | 71 |
| 507 | number | `2` | `3` | killed | 51 |
| 507 | number | `3` | `4` | killed | 8 |
| 542 | string | `"!H"` | `'!H_mutated'` | survived | 0 |
| 597 | number | `0x16` | `23` | killed | 1 |

### `ja4plus/utils/ssh_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 45 | number | `65536` | `65537` | survived | 0 |
| 273 | compare | `is` | `is not` | killed | 1 |
| 324 | string | `"version_string"` | `'version_string_mutated'` | killed | 1 |
| 335 | number | `2` | `3` | survived | 0 |
| 337 | bytes | `b"SSH_MSG_KEXINIT"` | `b'SSH_MSG_KEXINIT\x00'` | survived | 0 |
| 368 | bytes | `b"SSH_MSG_KEXINIT"` | `b'SSH_MSG_KEXINIT\x00'` | survived | 0 |
| 379 | number | `4` | `5` | killed | 10 |
| 462 | compare | `==` | `!=` | killed | 10 |
| 467 | binop | `+` | `-` | killed | 9 |
| 495 | number | `4` | `5` | survived | 0 |
| 511 | compare | `<=` | `<` | survived | 0 |
| 517 | number | `1` | `2` | survived | 0 |

### `ja4plus/utils/tcp_stream.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 38 | number | `4096` | `4097` | survived | 0 |
| 130 | string | `"bytes"` | `'bytes_mutated'` | killed | 348 |
| 136 | string | `"segments"` | `'segments_mutated'` | killed | 345 |
| 157 | number | `1` | `2` | killed | 5 |
| 166 | binop | `&` | `\|` | killed | 81 |
| 168 | binop | `-` | `+` | killed | 117 |
| 168 | number | `0` | `1` | killed | 117 |
| 173 | binop | `+` | `-` | killed | 117 |
| 196 | binop | `-` | `+` | killed | 102 |
| 196 | binop | `&` | `\|` | killed | 102 |
| 199 | binop | `+` | `-` | killed | 81 |
| 199 | binop | `&` | `\|` | killed | 81 |

### `ja4plus/utils/tls_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 70 | binop | `+` | `-` | killed | 982 |
| 160 | number | `8` | `9` | survived | 0 |
| 195 | string | `"signature_algorithms"` | `'signature_algorithms_mutated'` | killed | 660 |
| 224 | number | `1` | `2` | killed | 202 |
| 250 | compare | `<=` | `<` | killed | 22 |
| 253 | number | `4` | `5` | killed | 193 |
| 268 | binop | `<<` | `>>` | killed | 142 |
| 275 | string | `"alpn_protocols"` | `'alpn_protocols_mutated'` | survived | 0 |
| 309 | compare | `<=` | `<` | killed | 2 |
| 311 | bool | `True` | `False` | survived | 0 |
| 331 | number | `8` | `9` | killed | 630 |
| 397 | binop | `+` | `-` | killed | 660 |

### `ja4plus/utils/tunnels.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 23 | string | `"scapy.contrib.geneve"` | `'scapy.contrib.geneve_mutated'` | killed | 7 |
| 23 | string | `"scapy.layers.vxlan"` | `'scapy.layers.vxlan_mutated'` | survived | 0 |
| 23 | string | `"scapy.contrib.erspan"` | `'scapy.contrib.erspan_mutated'` | killed | 9 |

### `ja4plus/utils/x509_utils.py`

| Line | Kind | Before | After | Result | Cases killed |
|---|---|---|---|---|---|
| 35 | compare | `<` | `<=` | survived | 0 |
| 67 | number | `8` | `9` | survived | 0 |
| 91 | number | `0` | `1` | survived | 0 |
| 97 | binop | `&` | `\|` | survived | 0 |
| 101 | compare | `<` | `<=` | survived | 0 |
| 105 | number | `0x82` | `131` | survived | 0 |
| 107 | binop | `+` | `-` | survived | 0 |
| 107 | binop | `\|` | `&` | survived | 0 |
| 111 | number | `16` | `17` | survived | 0 |
| 111 | binop | `+` | `-` | survived | 0 |
| 111 | number | `4` | `5` | survived | 0 |
| 167 | number | `1` | `2` | killed | 61 |

## Every candidate

### `tests/fuzz/test_malformed_captures.py` — 2 candidates

- `tests/fuzz/test_malformed_captures.py::test_a_foxio_malformed_capture_reaches_the_parser_it_names[CVE-2018-6794.pcap]`
- `tests/fuzz/test_malformed_captures.py::test_a_foxio_malformed_capture_reaches_the_parser_it_names[badcurveball.pcap]`

### `tests/fuzz/test_truncated_captures.py` — 40 candidates

- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.1-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.1-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.1-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.1-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.5-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.5-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.5-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.5-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.9-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.9-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.9-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_copy_differs_from_the_committed_capture[0.9-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_frame_reaches_the_tls_parser[CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_frame_reaches_the_tls_parser[badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_frame_reaches_the_tls_parser[ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_frame_reaches_the_tls_parser[ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_http_payload_reaches_the_http_parser[0.1]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_http_payload_reaches_the_http_parser[0.5]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_http_payload_reaches_the_http_parser[0.9]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.1-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.1-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.1-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.5-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.5-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.5-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.9-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.9-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_produces_no_fingerprint_the_capture_lacks[0.9-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.1-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.1-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.1-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.1-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.5-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.5-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.5-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.5-ssh2-moloch-crash.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.9-CVE-2018-6794.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.9-badcurveball.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.9-ssh2-malformed.pcap]`
- `tests/fuzz/test_truncated_captures.py::test_a_truncated_payload_reaches_the_tls_parser[0.9-ssh2-moloch-crash.pcap]`

### `tests/test_cleanup_connection.py` — 8 candidates

- `tests/test_cleanup_connection.py::TestBaseFingerprinterCleanup::test_base_cleanup_is_noop`
- `tests/test_cleanup_connection.py::TestBaseFingerprinterCleanup::test_base_has_cleanup_connection`
- `tests/test_cleanup_connection.py::TestJA4HCleanup::test_cleanup_nonexistent_is_safe`
- `tests/test_cleanup_connection.py::TestJA4LCleanup::test_cleanup_nonexistent_is_safe`
- `tests/test_cleanup_connection.py::TestJA4SCleanup::test_cleanup_already_covered_in_quic_tests`
- `tests/test_cleanup_connection.py::TestJA4SSHCleanup::test_cleanup_nonexistent_is_safe`
- `tests/test_cleanup_connection.py::TestJA4XCleanup::test_cleanup_nonexistent_is_safe`
- `tests/test_cleanup_connection.py::TestJA4XCleanup::test_cleanup_removes_stream`

### `tests/test_cli.py` — 6 candidates

- `tests/test_cli.py::TestAnalyzePcap::test_analyze_types_filter`
- `tests/test_cli.py::TestCertCommand::test_cert_command`
- `tests/test_cli.py::TestCertCommand::test_cert_file_not_found`
- `tests/test_cli.py::TestCertCommand::test_cert_json_format`
- `tests/test_cli.py::TestInvalidTypes::test_valid_types_accepted`
- `tests/test_cli.py::TestVersionFlag::test_version_flag`

### `tests/test_comprehensive.py` — 28 candidates

- `tests/test_comprehensive.py::TestGREASE::test_all_grease_values_detected`
- `tests/test_comprehensive.py::TestGREASE::test_grease_edge_cases`
- `tests/test_comprehensive.py::TestGREASE::test_grease_string_hex`
- `tests/test_comprehensive.py::TestGREASE::test_non_grease_values_not_detected`
- `tests/test_comprehensive.py::TestJA4Comprehensive::test_non_tls_packet_returns_none`
- `tests/test_comprehensive.py::TestJA4LComprehensive::test_distance_km`
- `tests/test_comprehensive.py::TestJA4LComprehensive::test_distance_miles`
- `tests/test_comprehensive.py::TestJA4LComprehensive::test_hop_count_all_ranges`
- `tests/test_comprehensive.py::TestJA4LComprehensive::test_os_estimation_all_ranges`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_hassh_known_lookup`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_hassh_unknown_lookup`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_interpret_file_transfer`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_interpret_interactive`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_interpret_invalid_format`
- `tests/test_comprehensive.py::TestJA4SSHComprehensive::test_interpret_upload`
- `tests/test_comprehensive.py::TestJA4TComprehensive::test_ack_not_syn_ignored`
- `tests/test_comprehensive.py::TestJA4TComprehensive::test_no_options`
- `tests/test_comprehensive.py::TestJA4TComprehensive::test_synack_rejected_by_ja4t`
- `tests/test_comprehensive.py::TestJA4TSComprehensive::test_collector_uses_base`
- `tests/test_comprehensive.py::TestJA4TSComprehensive::test_syn_only_ignored`
- `tests/test_comprehensive.py::TestJA4XComprehensive::test_different_certs_different_fingerprints`
- `tests/test_comprehensive.py::TestJA4XComprehensive::test_fingerprint_format`
- `tests/test_comprehensive.py::TestJA4XComprehensive::test_no_extensions_cert`
- `tests/test_comprehensive.py::TestJA4XComprehensive::test_same_cert_same_fingerprint`
- `tests/test_comprehensive.py::TestTLSParsing::test_empty_data`
- `tests/test_comprehensive.py::TestTLSParsing::test_non_handshake_record_type`
- `tests/test_comprehensive.py::TestTLSParsing::test_too_short`
- `tests/test_comprehensive.py::TestTLSParsing::test_truncated_client_hello`

### `tests/test_edge_cases.py` — 40 candidates

- `tests/test_edge_cases.py::TestAllFingerprinterGraceful::test_all_reset_works`
- `tests/test_edge_cases.py::TestBaseFingerprinter::test_initial_state`
- `tests/test_edge_cases.py::TestBaseFingerprinter::test_process_packet_raises`
- `tests/test_edge_cases.py::TestBaseFingerprinter::test_reset`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4_empty_tls_info`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4_none_tls_info`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4_wrong_type`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4h_no_raw`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4h_non_http_packet`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4l_no_conn`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4l_no_ip`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4s_no_raw`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4s_non_tls_packet`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4ssh_no_tcp`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4t_no_ip`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4t_no_tcp`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4ts_no_tcp`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4x_empty_cert_info`
- `tests/test_edge_cases.py::TestEmptyInputs::test_ja4x_none_cert_info`
- `tests/test_edge_cases.py::TestJA4LEdgeCases::test_hop_count_zero_hops`
- `tests/test_edge_cases.py::TestJA4LEdgeCases::test_synack_before_syn`
- `tests/test_edge_cases.py::TestJA4LEdgeCases::test_ttl_boundary_values`
- `tests/test_edge_cases.py::TestMalformedSSH::test_empty_payload`
- `tests/test_edge_cases.py::TestMalformedSSH::test_http_data_to_ssh`
- `tests/test_edge_cases.py::TestMalformedSSH::test_tls_data_to_ssh`
- `tests/test_edge_cases.py::TestMalformedTCP::test_ja4t_push_ack_packet`
- `tests/test_edge_cases.py::TestMalformedTCP::test_ja4t_rst_packet`
- `tests/test_edge_cases.py::TestMalformedTCP::test_ja4t_synack_rejected`
- `tests/test_edge_cases.py::TestMalformedTCP::test_ja4ts_ack_only`
- `tests/test_edge_cases.py::TestMalformedTCP::test_ja4ts_syn_only`
- `tests/test_edge_cases.py::TestMalformedTLS::test_random_bytes`
- `tests/test_edge_cases.py::TestMalformedTLS::test_single_byte_data`
- `tests/test_edge_cases.py::TestMalformedTLS::test_truncated_tls_record`
- `tests/test_edge_cases.py::TestMalformedTLS::test_very_large_packet`
- `tests/test_edge_cases.py::TestMalformedTLS::test_wrong_record_type`
- `tests/test_edge_cases.py::TestMalformedTLS::test_zero_length_record`
- `tests/test_edge_cases.py::TestX509EdgeCases::test_empty_der_data`
- `tests/test_edge_cases.py::TestX509EdgeCases::test_generate_ja4x_empty_lists`
- `tests/test_edge_cases.py::TestX509EdgeCases::test_invalid_der_data`
- `tests/test_edge_cases.py::TestX509EdgeCases::test_text_data`

### `tests/test_foxio_deviations.py` — 111 candidates

- `tests/test_foxio_deviations.py::TestTheCommittedRegister::test_every_entry_names_an_issue`
- `tests/test_foxio_deviations.py::TestTheCommittedRegister::test_every_entry_states_a_cause`
- `tests/test_foxio_deviations.py::TestTheCommittedRegister::test_the_register_holds_no_duplicate_key`
- `tests/test_foxio_deviations.py::TestTheCommittedRegister::test_the_register_reads`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_cleartext_http1_vector_carries_no_entry`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[chrome-cloudflare-quic-with-secrets.pcapng/JA4H]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[chrome-cloudflare-quic-with-secrets.pcapng/JA4H_ro]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.10]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.11]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.12]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.13]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.14]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.15]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.2]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.3]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.4]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.5]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.6]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.7]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.8]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H.9]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.10]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.11]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.12]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.13]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.14]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.15]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.2]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.3]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.4]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.5]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.6]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.7]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.8]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/0:58847/JA4H_ro.9]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/JA4H]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_names_the_no_decryption_issue[http2-with-cookies.pcapng/JA4H_ro]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[chrome-cloudflare-quic-with-secrets.pcapng/0:57098/JA4H_ro.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[chrome-cloudflare-quic-with-secrets.pcapng/JA4H]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[chrome-cloudflare-quic-with-secrets.pcapng/JA4H_ro]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.10]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.11]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.12]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.13]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.14]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.15]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.2]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.3]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.4]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.5]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.6]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.7]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.8]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H.9]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.10]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.11]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.12]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.13]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.14]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.15]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.1]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.2]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.3]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.4]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.5]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.6]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.7]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.8]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/0:58847/JA4H_ro.9]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/JA4H]`
- `tests/test_foxio_deviations.py::TestTheEncryptedHttpDeviations::test_the_entry_states_that_ja4plus_reads_no_encrypted_request[http2-with-cookies.pcapng/JA4H_ro]`
- `tests/test_foxio_deviations.py::TestTheKeyForms::test_the_occurrence_key_names_the_vector_and_the_method`
- `tests/test_foxio_deviations.py::TestTheKeyForms::test_the_two_key_forms_never_collide`
- `tests/test_foxio_deviations.py::TestTheKeyForms::test_the_value_key_accepts_an_unknown_stream_index`
- `tests/test_foxio_deviations.py::TestTheKeyForms::test_the_value_key_names_the_vector_the_stream_and_the_occurrence`
- `tests/test_foxio_deviations.py::TestTheKeyForms::test_the_value_key_separates_two_streams_that_share_one_index`
- `tests/test_foxio_deviations.py::TestTheOwnerReader::test_the_reader_keys_the_map_by_issue_number`
- `tests/test_foxio_deviations.py::TestTheOwnerReader::test_the_reader_reads_no_epic_flag_as_false`
- `tests/test_foxio_deviations.py::TestTheOwnerReader::test_the_reader_rejects_a_state_it_does_not_allow`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_every_decided_entry_names_the_implementation_that_holds_the_value`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_every_decided_entry_states_why_the_python_file_omits_the_stream`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_every_settled_entry_is_decided`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_no_settled_entry_names_the_epic`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_the_issue_owns_every_entry_it_settled`
- `tests/test_foxio_deviations.py::TestTheReferenceOmitsTheStreamDeviations::test_the_tunnel_scan_entry_states_the_decision_that_keeps_the_values`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_no_entry_names_an_epic_or_a_closed_issue`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_check_accepts_a_decided_entry_that_names_a_closed_issue`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_check_accepts_an_open_issue`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_check_reports_an_entry_that_names_a_closed_issue`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_check_reports_an_entry_that_names_an_epic`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_check_reports_an_owner_the_list_does_not_hold`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_owner_list_holds_every_issue_the_register_names`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_owner_list_reads`
- `tests/test_foxio_deviations.py::TestTheRegisterOwners::test_the_owner_list_records_where_it_came_from`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_reads_no_decided_flag_as_false`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_reads_the_decided_flag`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_rejects_a_decided_flag_that_is_not_a_boolean`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_rejects_an_entry_that_is_not_a_table`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_rejects_an_entry_that_names_no_issue`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_rejects_an_entry_that_states_no_cause`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_rejects_an_issue_number_that_is_not_a_number`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_returns_an_empty_register_for_a_missing_file`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_returns_an_empty_register_for_an_empty_file`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reader_returns_one_entry_for_one_key`
- `tests/test_foxio_deviations.py::TestTheRegisterReader::test_the_reason_names_the_issue_and_the_cause`

### `tests/test_foxio_manifest.py` — 12 candidates

- `tests/test_foxio_manifest.py::TestTheCommittedManifest::test_every_entry_names_a_capture_file`
- `tests/test_foxio_manifest.py::TestTheCommittedManifest::test_the_manifest_reads`
- `tests/test_foxio_manifest.py::TestTheComparison::test_the_comparison_names_a_vector_the_manifest_does_not_hold`
- `tests/test_foxio_manifest.py::TestTheComparison::test_the_comparison_names_a_vector_the_suite_did_not_collect`
- `tests/test_foxio_manifest.py::TestTheComparison::test_the_comparison_names_a_vector_whose_case_count_changed`
- `tests/test_foxio_manifest.py::TestTheComparison::test_the_comparison_reports_every_difference`
- `tests/test_foxio_manifest.py::TestTheComparison::test_the_comparison_reports_nothing_when_the_two_agree`
- `tests/test_foxio_manifest.py::TestTheManifestReader::test_the_reader_accepts_a_vector_that_carries_no_case`
- `tests/test_foxio_manifest.py::TestTheManifestReader::test_the_reader_rejects_a_count_that_is_not_a_number`
- `tests/test_foxio_manifest.py::TestTheManifestReader::test_the_reader_rejects_a_negative_count`
- `tests/test_foxio_manifest.py::TestTheManifestReader::test_the_reader_rejects_an_absent_manifest`
- `tests/test_foxio_manifest.py::TestTheManifestReader::test_the_reader_returns_the_case_count_of_each_vector`

### `tests/test_foxio_rust_parity.py` — 17 candidates

- `tests/test_foxio_rust_parity.py::TestTheFoxioPythonImplementationReadsNoQuic::test_the_python_expected_output_holds_no_quic_value`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[browsers-x509.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[chrome-cloudflare-quic-with-secrets.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[https-connect.pcap]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[latest.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[quic-tls-handshake.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[quic-with-several-tls-frames.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[ssh2.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[tls-handshake.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[tls-sni.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheRustImplementationHoldsWhatJa4plusProduces::test_the_capture_holds_a_stream_the_python_file_omits[tls3.pcapng]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[browsers-x509.pcapng:54524]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[latest.pcapng:52940]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[latest.pcapng:52941]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[ssh2.pcapng:57374]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[ssh2.pcapng:57375]`
- `tests/test_foxio_rust_parity.py::TestTheStreamsThatCoalesceTheServerHelloRecord::test_the_foxio_python_file_omits_the_stream[tls-handshake.pcapng:50167]`

### `tests/test_generate_foxio_baseline.py` — 22 candidates

- `tests/test_generate_foxio_baseline.py::TestTheCommittedEntry::test_a_committed_entry_keeps_the_decided_field`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedEntry::test_a_committed_entry_keeps_the_order_of_its_fields`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedEntry::test_a_committed_entry_survives_the_regeneration`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedEntry::test_a_key_that_stops_failing_leaves_the_register`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedEntry::test_a_new_key_gets_the_cause_the_failure_message_states`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedRegisterAfterARun::test_a_run_that_finds_the_same_deviations_writes_the_same_bytes`
- `tests/test_generate_foxio_baseline.py::TestTheCommittedRegisterAfterARun::test_the_run_keeps_every_decided_entry`
- `tests/test_generate_foxio_baseline.py::TestTheFailureLineReader::test_the_reader_drops_the_source_that_holds_the_format_string`
- `tests/test_generate_foxio_baseline.py::TestTheFailureLineReader::test_the_reader_returns_the_failure_line`
- `tests/test_generate_foxio_baseline.py::TestTheFailureLineReader::test_the_reader_returns_the_report_when_it_holds_no_failure_line`
- `tests/test_generate_foxio_baseline.py::TestTheJA4LOwner::test_a_missing_occurrence_key_names_the_mirrored_capture`
- `tests/test_generate_foxio_baseline.py::TestTheJA4LOwner::test_a_produced_none_names_the_mirrored_capture`
- `tests/test_generate_foxio_baseline.py::TestTheJA4LOwner::test_a_server_latency_of_another_amount_names_the_quic_server_point`
- `tests/test_generate_foxio_baseline.py::TestTheJA4LOwner::test_an_extra_client_occurrence_key_names_the_multiplicity_issue`
- `tests/test_generate_foxio_baseline.py::TestTheJA4LOwner::test_an_extra_server_occurrence_key_names_the_multiplicity_issue`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_a_JA4H_ro_failure_names_the_absent_raw_form`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_a_JA4H_ro_occurrence_failure_names_the_absent_raw_form`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_a_JA4S_r_mismatch_names_the_issue_of_the_hashed_form`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_a_JA4_r_mismatch_names_the_issue_of_the_hashed_form`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_a_zero_extension_hash_names_the_JA4_o_reading`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfARawForm::test_another_JA4_o_mismatch_names_the_issue_of_the_hashed_form`
- `tests/test_generate_foxio_baseline.py::TestTheOwnerOfAnotherMethod::test_a_JA4X_value_mismatch_names_its_issue_and_the_mismatch`

### `tests/test_integration.py` — 1 candidates

- `tests/test_integration.py::TestIntegration::test_all_fingerprinters_reset`

### `tests/test_ipv6_support.py` — 1 candidates

- `tests/test_ipv6_support.py::TestJA4TSIPv6::test_ja4ts_ipv6`

### `tests/test_ja4.py` — 2 candidates

- `tests/test_ja4.py::TestJA4::test_basic_functionality`
- `tests/test_ja4.py::TestJA4::test_client_hello_fingerprint`

### `tests/test_ja4_alpn.py` — 15 candidates

- `tests/test_ja4_alpn.py::test_compute_alpn_value[ -20]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[ a-21]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[-00]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[01\xab\xcd-3d]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[0\xab-3b]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[0\xab\xcd1-01]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[\xab-ab]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[\xab\xcd-ad]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[a -60]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[h-hh]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[h2-h2]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[h3-h3]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value[http/1.1-h1]`
- `tests/test_ja4_alpn.py::test_compute_alpn_value_none_returns_00`
- `tests/test_ja4_alpn.py::test_the_pcap_vector_alpn_value_is_99`

### `tests/test_ja4_alpn_condition.py` — 29 candidates

- `tests/test_ja4_alpn_condition.py::test_a_byte_outside_ascii_keeps_the_value_99_while_the_references_disagree[01\xab\xcd]`
- `tests/test_ja4_alpn_condition.py::test_a_byte_outside_ascii_keeps_the_value_99_while_the_references_disagree[\xabh]`
- `tests/test_ja4_alpn_condition.py::test_a_byte_outside_ascii_keeps_the_value_99_while_the_references_disagree[h\xab]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[\x00\x01]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[\x01h]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[h\n]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[h\x00]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[h\x01]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[h\x1f]`
- `tests/test_ja4_alpn_condition.py::test_a_control_byte_keeps_the_value_99_while_the_references_disagree[h\x7f]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[ h- h]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[\xba\xad-99]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[h  2-h2]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[h -h ]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[h!-h!]`
- `tests/test_ja4_alpn_condition.py::test_a_printable_ascii_byte_reaches_the_alpn_value_without_a_change[h~-h~]`
- `tests/test_ja4_alpn_condition.py::test_each_register_entry_states_the_output_of_both_foxio_implementations[stream2-68ab]`
- `tests/test_ja4_alpn_condition.py::test_each_register_entry_states_the_output_of_both_foxio_implementations[stream4-681f]`
- `tests/test_ja4_alpn_condition.py::test_each_register_entry_states_the_output_of_both_foxio_implementations[stream5-680a]`
- `tests/test_ja4_alpn_condition.py::test_each_register_entry_states_the_output_of_both_foxio_implementations[stream6-68]`
- `tests/test_ja4_alpn_condition.py::test_every_stream_differs_from_the_others_in_the_alpn_characters_alone`
- `tests/test_ja4_alpn_condition.py::test_the_agreed_streams_carry_no_register_entry`
- `tests/test_ja4_alpn_condition.py::test_the_deviation_register_holds_each_disputed_stream[stream2-68ab]`
- `tests/test_ja4_alpn_condition.py::test_the_deviation_register_holds_each_disputed_stream[stream4-681f]`
- `tests/test_ja4_alpn_condition.py::test_the_deviation_register_holds_each_disputed_stream[stream5-680a]`
- `tests/test_ja4_alpn_condition.py::test_the_deviation_register_holds_each_disputed_stream[stream6-68]`
- `tests/test_ja4_alpn_condition.py::test_the_expected_file_holds_one_entry_for_each_stream`
- `tests/test_ja4_alpn_condition.py::test_the_expected_file_holds_the_foxio_python_alpn_characters`
- `tests/test_ja4_alpn_condition.py::test_the_tab_byte_keeps_the_value_99_although_the_references_agree`

### `tests/test_ja4_deep.py` — 37 candidates

- `tests/test_ja4_deep.py::TestJA4ALPN::test_empty_first_protocol_gives_00`
- `tests/test_ja4_deep.py::TestJA4ALPN::test_h2_gives_h2`
- `tests/test_ja4_deep.py::TestJA4ALPN::test_http11_gives_h1`
- `tests/test_ja4_deep.py::TestJA4ALPN::test_multiple_alpn_uses_first`
- `tests/test_ja4_deep.py::TestJA4ALPN::test_no_alpn_gives_00`
- `tests/test_ja4_deep.py::TestJA4ALPN::test_single_char_protocol`
- `tests/test_ja4_deep.py::TestJA4CipherHash::test_ciphers_sorted_for_hash`
- `tests/test_ja4_deep.py::TestJA4CipherHash::test_empty_ciphers_give_zeros`
- `tests/test_ja4_deep.py::TestJA4CipherHash::test_single_cipher`
- `tests/test_ja4_deep.py::TestJA4CountCapping::test_cipher_count_capped_at_99`
- `tests/test_ja4_deep.py::TestJA4CountCapping::test_extension_count_capped_at_99`
- `tests/test_ja4_deep.py::TestJA4ExtensionHash::test_extensions_sorted`
- `tests/test_ja4_deep.py::TestJA4ExtensionHash::test_no_extensions_give_zeros`
- `tests/test_ja4_deep.py::TestJA4FingerprinterClass::test_reset`
- `tests/test_ja4_deep.py::TestJA4Format::test_hash_parts_are_12_chars`
- `tests/test_ja4_deep.py::TestJA4Format::test_part_a_length`
- `tests/test_ja4_deep.py::TestJA4Format::test_three_parts`
- `tests/test_ja4_deep.py::TestJA4GREASEFiltering::test_grease_ciphers_excluded_from_count`
- `tests/test_ja4_deep.py::TestJA4GREASEFiltering::test_grease_ciphers_excluded_from_hash`
- `tests/test_ja4_deep.py::TestJA4GREASEFiltering::test_grease_extensions_excluded_from_count`
- `tests/test_ja4_deep.py::TestJA4GREASEFiltering::test_grease_in_supported_versions_filtered`
- `tests/test_ja4_deep.py::TestJA4Protocol::test_dtls_protocol`
- `tests/test_ja4_deep.py::TestJA4Protocol::test_quic_protocol`
- `tests/test_ja4_deep.py::TestJA4Protocol::test_tcp_protocol`
- `tests/test_ja4_deep.py::TestJA4RawFingerprint::test_raw_none_returns_none`
- `tests/test_ja4_deep.py::TestJA4RawFingerprint::test_raw_not_client_hello_returns_none`
- `tests/test_ja4_deep.py::TestJA4SNI::test_sni_absent_uses_i`
- `tests/test_ja4_deep.py::TestJA4SNI::test_sni_empty_string_uses_i`
- `tests/test_ja4_deep.py::TestJA4SNI::test_sni_present_uses_d`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_dtls10`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_dtls12`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_ssl20`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_supported_versions_overrides_protocol_version`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_tls10`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_tls11`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_tls12`
- `tests/test_ja4_deep.py::TestJA4VersionMapping::test_tls13`

### `tests/test_ja4_empty_ext.py` — 3 candidates

- `tests/test_ja4_empty_ext.py::test_ja4_empty_extensions_yields_literal_zero_hash`
- `tests/test_ja4_empty_ext.py::test_ja4_only_grease_extensions_yields_literal_zero_hash`
- `tests/test_ja4_empty_ext.py::test_ja4_original_order_hashes_the_wire_order_when_another_extension_is_present`

### `tests/test_ja4_hello_retry.py` — 2 candidates

- `tests/test_ja4_hello_retry.py::test_the_reader_returns_nothing_when_a_record_length_overruns_the_buffer`
- `tests/test_ja4_hello_retry.py::test_the_reader_returns_nothing_when_no_record_holds_a_hello`

### `tests/test_ja4_raw_branches.py` — 1 candidates

- `tests/test_ja4_raw_branches.py::test_no_branch_of_the_ja4_module_builds_one_string_in_both_arms`

### `tests/test_ja4d.py` — 14 candidates

- `tests/test_ja4d.py::TestBuildOptionList::test_all_skipped`
- `tests/test_ja4d.py::TestBuildOptionList::test_empty`
- `tests/test_ja4d.py::TestBuildOptionList::test_multiple_options`
- `tests/test_ja4d.py::TestBuildOptionList::test_single_option`
- `tests/test_ja4d.py::TestBuildOptionList::test_skip_set_respected`
- `tests/test_ja4d.py::TestBuildOptionList::test_with_skipped_mixed`
- `tests/test_ja4d.py::TestBuildParamList::test_empty`
- `tests/test_ja4d.py::TestBuildParamList::test_multiple`
- `tests/test_ja4d.py::TestBuildParamList::test_single`
- `tests/test_ja4d.py::TestDHCPMessageTypes::test_all_18_types_present`
- `tests/test_ja4d.py::TestGenerateJA4D::test_non_dhcp_port_returns_none`
- `tests/test_ja4d.py::TestGenerateJA4D::test_tcp_packet_returns_none`
- `tests/test_ja4d.py::TestJA4DFingerprinter::test_cleanup_connection_is_noop`
- `tests/test_ja4d.py::TestJA4DFingerprinter::test_non_dhcp_returns_none`

### `tests/test_ja4d6_foxio.py` — 2 candidates

- `tests/test_ja4d6_foxio.py::test_fingerprinter_class_collects_results`
- `tests/test_ja4d6_foxio.py::test_non_dhcpv6_port_returns_none`

### `tests/test_ja4db.py` — 4 candidates

- `tests/test_ja4db.py::TestCLILookupFlag::test_analyze_with_lookup_json`
- `tests/test_ja4db.py::TestCLILookupFlag::test_analyze_without_lookup_json`
- `tests/test_ja4db.py::TestJA4DBClient::test_lookup_cache_hit`
- `tests/test_ja4db.py::TestJA4DBClient::test_remote_lookup_timeout`

### `tests/test_ja4h_cookie_list.py` — 6 candidates

- `tests/test_ja4h_cookie_list.py::test_a_cookie_header_with_no_repeated_name_keeps_its_fingerprint`
- `tests/test_ja4h_cookie_list.py::test_a_repeated_cookie_name_reaches_both_hashes_of_the_packet_path`
- `tests/test_ja4h_cookie_list.py::test_a_request_line_that_names_no_version_produces_no_fingerprint`
- `tests/test_ja4h_cookie_list.py::test_a_request_line_with_a_minor_version_keeps_its_version_code`
- `tests/test_ja4h_cookie_list.py::test_a_request_line_without_a_minor_version_produces_the_version_code_20`
- `tests/test_ja4h_cookie_list.py::test_the_packet_path_reads_a_request_line_without_a_minor_version`

### `tests/test_ja4h_deep.py` — 26 candidates

- `tests/test_ja4h_deep.py::TestJA4HCookieHash::test_cookie_fields_sorted`
- `tests/test_ja4h_deep.py::TestJA4HCookieHash::test_cookie_values_sorted_by_name`
- `tests/test_ja4h_deep.py::TestJA4HCookieHash::test_no_cookies_gives_zeros`
- `tests/test_ja4h_deep.py::TestJA4HCookieHash::test_single_cookie`
- `tests/test_ja4h_deep.py::TestJA4HCookieIndicator::test_cookie_absent`
- `tests/test_ja4h_deep.py::TestJA4HCookieIndicator::test_cookie_present`
- `tests/test_ja4h_deep.py::TestJA4HCookieIndicator::test_multiple_cookies`
- `tests/test_ja4h_deep.py::TestJA4HFormat::test_all_hash_parts_12_chars`
- `tests/test_ja4h_deep.py::TestJA4HFormat::test_non_http_returns_none`
- `tests/test_ja4h_deep.py::TestJA4HHeaderCount::test_header_count_two_digit_format`
- `tests/test_ja4h_deep.py::TestJA4HHeaderHash::test_header_hash_computed`
- `tests/test_ja4h_deep.py::TestJA4HHeaderHash::test_no_headers_gives_zeros`
- `tests/test_ja4h_deep.py::TestJA4HLanguageExtraction::test_no_language`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_connect`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_delete`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_get`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_head`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_options`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_patch`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_post`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_put`
- `tests/test_ja4h_deep.py::TestJA4HMethodEncoding::test_trace`
- `tests/test_ja4h_deep.py::TestJA4HRefererIndicator::test_referer_absent`
- `tests/test_ja4h_deep.py::TestJA4HVersionParsing::test_http10`
- `tests/test_ja4h_deep.py::TestJA4HVersionParsing::test_http11`
- `tests/test_ja4h_deep.py::TestJA4HVersionParsing::test_http20`

### `tests/test_ja4h_raw.py` — 5 candidates

- `tests/test_ja4h_raw.py::test_the_fingerprinter_reports_no_raw_value_before_it_reads_a_request`
- `tests/test_ja4h_raw.py::test_the_raw_form_ends_after_the_header_names_when_no_cookie_is_present`
- `tests/test_ja4h_raw.py::test_the_raw_form_holds_the_cookie_names_in_wire_order`
- `tests/test_ja4h_raw.py::test_the_raw_form_keeps_a_repeated_cookie_name`
- `tests/test_ja4h_raw.py::test_the_raw_form_reports_nothing_for_an_empty_info`

### `tests/test_ja4h_spec.py` — 15 candidates

- `tests/test_ja4h_spec.py::test_cookie_values_hash_input_form_is_name_value_pairs_sorted_by_name`
- `tests/test_ja4h_spec.py::test_cookie_values_hash_sorts_by_name_only`
- `tests/test_ja4h_spec.py::test_every_reference_value_of_the_foxio_capture_carries_the_version_code_20`
- `tests/test_ja4h_spec.py::test_http_version_in_part_a_for_http11`
- `tests/test_ja4h_spec.py::test_http_version_in_part_a_for_http2`
- `tests/test_ja4h_spec.py::test_http_version_in_part_a_for_http3`
- `tests/test_ja4h_spec.py::test_http_version_mapping[-11]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/1.0-10]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/1.1-11]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/2-20]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/2.0-20]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/3-30]`
- `tests/test_ja4h_spec.py::test_http_version_mapping[HTTP/3.0-30]`
- `tests/test_ja4h_spec.py::test_the_foxio_capture_carries_no_cleartext_http_request`
- `tests/test_ja4h_spec.py::test_the_foxio_capture_produces_the_reference_ja4h_values`

### `tests/test_ja4l.py` — 8 candidates

- `tests/test_ja4l.py::TestJA4L::test_ja4l_distance_calculation`
- `tests/test_ja4l.py::TestJA4L::test_ja4l_hop_count`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_an_explicit_propagation_factor_overrides_the_table`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_clamps_a_negative_hop_count_to_zero_hops`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_keeps_the_factor_1_6_when_the_caller_passes_no_ttl`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_reads_a_different_distance_for_20_hops_and_for_30_hops`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_reads_the_factor_2_0_for_a_hop_count_above_26`
- `tests/test_ja4l.py::TestJA4LPropagationFactor::test_reads_the_foxio_table_for_a_distance_in_kilometers`

### `tests/test_ja4l_connection_state.py` — 1 candidates

- `tests/test_ja4l_connection_state.py::test_a_capture_that_starts_after_the_handshake_reports_nothing`

### `tests/test_ja4l_udp_direction.py` — 2 candidates

- `tests/test_ja4l_udp_direction.py::test_the_fingerprinter_reports_nothing_for_a_udp_flow_that_carries_no_quic`
- `tests/test_ja4l_udp_direction.py::test_the_fingerprinter_reports_nothing_when_both_ports_are_443`

### `tests/test_ja4s.py` — 1 candidates

- `tests/test_ja4s.py::TestJA4S::test_basic_functionality`

### `tests/test_ja4ssh.py` — 2 candidates

- `tests/test_ja4ssh.py::TestJA4SSH::test_hassh_database`
- `tests/test_ja4ssh.py::TestJA4SSH::test_interpret_fingerprint`

### `tests/test_ja4ssh_deep.py` — 17 candidates

- `tests/test_ja4ssh_deep.py::TestJA4SSHFingerprinterClass::test_no_raw_layer_ignored`
- `tests/test_ja4ssh_deep.py::TestJA4SSHFingerprinterClass::test_no_tcp_ignored`
- `tests/test_ja4ssh_deep.py::TestJA4SSHFingerprinterClass::test_non_ssh_ignored`
- `tests/test_ja4ssh_deep.py::TestJA4SSHFingerprinterClass::test_packet_count_parameter`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSDatabase::test_known_cyberduck`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSDatabase::test_known_dropbear`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSDatabase::test_known_openssh`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSDatabase::test_known_paramiko`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSDatabase::test_unknown_hassh`
- `tests/test_ja4ssh_deep.py::TestJA4SSHHASSSExtraction::test_different_algorithms_different_hassh`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_detail_extraction`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_file_transfer_download`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_file_transfer_upload`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_interactive_interpretation`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_invalid_format`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_reverse_ssh`
- `tests/test_ja4ssh_deep.py::TestJA4SSHInterpretation::test_unknown_pattern`

### `tests/test_ja4ssh_direction.py` — 1 candidates

- `tests/test_ja4ssh_direction.py::TestSSHBareACKCounting::test_bare_acks_not_counted_for_unknown_connections`

### `tests/test_ja4ssh_interpret.py` — 15 candidates

- `tests/test_ja4ssh_interpret.py::test_a_fingerprint_that_is_none_returns_an_error_dictionary`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[a part that holds no server field]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[a size that holds no digit]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[an empty string]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[four parts]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[one part]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[three parts that hold no number]`
- `tests/test_ja4ssh_interpret.py::test_a_malformed_fingerprint_returns_an_error_dictionary[two parts]`
- `tests/test_ja4ssh_interpret.py::test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary[a packet size part that carries a wrong client prefix]`
- `tests/test_ja4ssh_interpret.py::test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary[a packet size part that carries no client prefix]`
- `tests/test_ja4ssh_interpret.py::test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary[an ACK ratio part that carries no client prefix]`
- `tests/test_ja4ssh_interpret.py::test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary[an SSH ratio part that carries a wrong client prefix]`
- `tests/test_ja4ssh_interpret.py::test_a_part_that_carries_no_client_prefix_returns_an_error_dictionary[an SSH ratio part that carries no client prefix]`
- `tests/test_ja4ssh_interpret.py::test_a_valid_fingerprint_still_reports_the_session_type`
- `tests/test_ja4ssh_interpret.py::test_an_error_the_parser_expects_from_no_input_reaches_the_caller`

### `tests/test_ja4ssh_message_count.py` — 19 candidates

- `tests/test_ja4ssh_message_count.py::test_a_banner_longer_than_the_limit_makes_the_tracker_count_every_segment`
- `tests/test_ja4ssh_message_count.py::test_a_banner_that_spans_two_segments_completes_on_the_second`
- `tests/test_ja4ssh_message_count.py::test_a_banner_that_spans_two_segments_keeps_the_message_boundary`
- `tests/test_ja4ssh_message_count.py::test_a_gap_that_never_fills_makes_the_tracker_count_every_segment`
- `tests/test_ja4ssh_message_count.py::test_a_length_field_that_spans_two_segments_completes_on_the_second`
- `tests/test_ja4ssh_message_count.py::test_a_retransmission_that_precedes_the_wrap_point_is_dropped`
- `tests/test_ja4ssh_message_count.py::test_a_retransmitted_segment_is_not_one_ssh_packet`
- `tests/test_ja4ssh_message_count.py::test_a_retransmitted_segment_keeps_the_message_boundary`
- `tests/test_ja4ssh_message_count.py::test_a_segment_that_holds_part_of_a_message_is_not_one_ssh_packet`
- `tests/test_ja4ssh_message_count.py::test_a_segment_that_holds_two_whole_messages_is_one_ssh_packet`
- `tests/test_ja4ssh_message_count.py::test_a_segment_that_repeats_part_of_the_stream_is_read_once`
- `tests/test_ja4ssh_message_count.py::test_an_empty_segment_is_not_one_ssh_packet`
- `tests/test_ja4ssh_message_count.py::test_an_out_of_order_segment_counts_on_its_own_sequence_number`
- `tests/test_ja4ssh_message_count.py::test_an_out_of_order_segment_that_follows_the_wrap_point_is_held`
- `tests/test_ja4ssh_message_count.py::test_an_unreadable_length_makes_the_tracker_count_every_segment`
- `tests/test_ja4ssh_message_count.py::test_the_held_segments_stay_below_the_byte_bound`
- `tests/test_ja4ssh_message_count.py::test_the_segment_that_completes_a_message_is_one_ssh_packet`
- `tests/test_ja4ssh_message_count.py::test_the_tracker_counts_every_segment_after_the_new_keys_message`
- `tests/test_ja4ssh_message_count.py::test_the_tracker_counts_every_segment_when_the_capture_holds_no_banner`

### `tests/test_ja4ssh_server_side.py` — 7 candidates

- `tests/test_ja4ssh_server_side.py::test_a_packet_that_carries_the_rst_flag_names_no_endpoint[a SYN and a RST]`
- `tests/test_ja4ssh_server_side.py::test_a_packet_that_carries_the_rst_flag_names_no_endpoint[a SYN, an ACK and a RST]`
- `tests/test_ja4ssh_server_side.py::test_one_reader_of_the_tcp_handshake_serves_both_fingerprinters`
- `tests/test_ja4ssh_server_side.py::test_the_fingerprint_entry_records_how_the_server_was_decided[a handshake]`
- `tests/test_ja4ssh_server_side.py::test_the_fingerprint_entry_records_how_the_server_was_decided[no handshake]`
- `tests/test_ja4ssh_server_side.py::test_the_handshake_table_forgets_a_connection_the_processor_cleans_up`
- `tests/test_ja4ssh_server_side.py::test_the_handshake_table_holds_no_more_than_its_maximum_entry_count`

### `tests/test_ja4ssh_spec.py` — 5 candidates

- `tests/test_ja4ssh_spec.py::test_mode_clear_winner_unaffected`
- `tests/test_ja4ssh_spec.py::test_mode_empty_list_returns_zero`
- `tests/test_ja4ssh_spec.py::test_mode_single_value`
- `tests/test_ja4ssh_spec.py::test_mode_three_way_tie_picks_lowest`
- `tests/test_ja4ssh_spec.py::test_mode_tie_picks_lowest_value`

### `tests/test_ja4ssh_windows.py` — 1 candidates

- `tests/test_ja4ssh_windows.py::test_a_fin_packet_on_an_unknown_connection_emits_nothing`

### `tests/test_ja4t.py` — 1 candidates

- `tests/test_ja4t.py::TestJA4T::test_different_window_sizes`

### `tests/test_ja4t_deep.py` — 15 candidates

- `tests/test_ja4t_deep.py::TestJA4TFingerprinterClass::test_reset`
- `tests/test_ja4t_deep.py::TestJA4TFlagFiltering::test_ack_rejected`
- `tests/test_ja4t_deep.py::TestJA4TFlagFiltering::test_push_ack_rejected`
- `tests/test_ja4t_deep.py::TestJA4TFlagFiltering::test_rst_rejected`
- `tests/test_ja4t_deep.py::TestJA4TFlagFiltering::test_syn_accepted`
- `tests/test_ja4t_deep.py::TestJA4TFlagFiltering::test_synack_rejected`
- `tests/test_ja4t_deep.py::TestJA4TFormat::test_no_options_format`
- `tests/test_ja4t_deep.py::TestJA4TSFingerprinterClass::test_collect`
- `tests/test_ja4t_deep.py::TestJA4TSFingerprinterClass::test_reset`
- `tests/test_ja4t_deep.py::TestJA4TSFlagFiltering::test_ack_rejected`
- `tests/test_ja4t_deep.py::TestJA4TSFlagFiltering::test_rst_rejected`
- `tests/test_ja4t_deep.py::TestJA4TSFlagFiltering::test_syn_rejected`
- `tests/test_ja4t_deep.py::TestJA4TSFlagFiltering::test_synack_accepted`
- `tests/test_ja4t_deep.py::TestJA4TWindowSizes::test_common_windows`
- `tests/test_ja4t_deep.py::TestJA4TWindowSizes::test_max_window`

### `tests/test_ja4ts.py` — 1 candidates

- `tests/test_ja4ts.py::TestJA4TS::test_non_synack_packets`

### `tests/test_ja4x_deep.py` — 17 candidates

- `tests/test_ja4x_deep.py::TestJA4XDeterminism::test_same_cert_same_result`
- `tests/test_ja4x_deep.py::TestJA4XDifferentStructures::test_different_extensions`
- `tests/test_ja4x_deep.py::TestJA4XDifferentStructures::test_different_issuer_oids`
- `tests/test_ja4x_deep.py::TestJA4XDifferentStructures::test_different_subject_oids`
- `tests/test_ja4x_deep.py::TestJA4XFingerprinterClass::test_fingerprint_certificate`
- `tests/test_ja4x_deep.py::TestJA4XFingerprinterClass::test_invalid_cert_data`
- `tests/test_ja4x_deep.py::TestJA4XFingerprinterClass::test_reset`
- `tests/test_ja4x_deep.py::TestJA4XFormat::test_each_part_12_chars`
- `tests/test_ja4x_deep.py::TestJA4XFormat::test_parts_are_hex`
- `tests/test_ja4x_deep.py::TestJA4XFormat::test_three_parts`
- `tests/test_ja4x_deep.py::TestJA4XGenerateFunction::test_empty_dict`
- `tests/test_ja4x_deep.py::TestJA4XGenerateFunction::test_manual_cert_info`
- `tests/test_ja4x_deep.py::TestJA4XGenerateFunction::test_none_input`
- `tests/test_ja4x_deep.py::TestJA4XNoExtensions::test_no_extensions_hash_is_zero_sentinel`
- `tests/test_ja4x_deep.py::TestJA4XNoExtensions::test_no_extensions_still_fingerprints`
- `tests/test_ja4x_deep.py::TestJA4XOIDHashing::test_same_structure_same_hash`
- `tests/test_ja4x_deep.py::TestJA4XSelfSignedVsCA::test_ca_signed_issuer_differs_from_subject`

### `tests/test_loopback_link_type.py` — 1 candidates

- `tests/test_loopback_link_type.py::test_dissects_every_bsd_address_family_value_as_ipv6[30]`

### `tests/test_no_retained_packets.py` — 2 candidates

- `tests/test_no_retained_packets.py::test_a_fingerprinter_holds_no_packet_after_it_reads_a_capture[JA4D6]`
- `tests/test_no_retained_packets.py::test_a_fingerprinter_holds_no_packet_after_it_reads_a_capture[JA4TS]`

### `tests/test_packet_utils.py` — 6 candidates

- `tests/test_packet_utils.py::TestGetIPLayer::test_ipv4_packet`
- `tests/test_packet_utils.py::TestGetIPLayer::test_ipv4_preferred_when_both`
- `tests/test_packet_utils.py::TestGetIPLayer::test_ipv6_packet`
- `tests/test_packet_utils.py::TestGetIPLayer::test_no_ip_returns_none`
- `tests/test_packet_utils.py::TestPacketSeconds::test_returns_none_when_the_packet_carries_no_time`
- `tests/test_packet_utils.py::TestPacketSeconds::test_returns_the_capture_timestamp_in_seconds`

### `tests/test_processor.py` — 2 candidates

- `tests/test_processor.py::test_processor_attribute_access_to_fingerprinters`
- `tests/test_processor.py::test_processor_cleanup_connection_propagates`

### `tests/test_quic_crypto_buffer_bound.py` — 15 candidates

- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_bounds_its_fragment_table_by_age`
- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_bounds_its_fragment_table_by_entry_count`
- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_cleanup_drops_the_age_entry`
- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_collects_no_fragment_past_the_limit`
- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_keeps_a_connection_inside_the_maximum_age`
- `tests/test_quic_crypto_buffer_bound.py::test_the_fingerprinter_reset_empties_every_fragment_table`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_allocates_no_more_than_the_limit`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_drops_a_fragment_past_the_limit`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_drops_a_fragment_that_ends_one_byte_past_the_limit`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_drops_the_highest_offset_the_rfc_encodes`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_keeps_the_real_fragment_beside_a_hostile_one`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_names_no_large_buffer_for_any_hostile_offset[28]`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_names_no_large_buffer_for_any_hostile_offset[34]`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_names_no_large_buffer_for_any_hostile_offset[40]`
- `tests/test_quic_crypto_buffer_bound.py::test_the_reassembler_names_no_large_buffer_for_any_hostile_offset[62]`

### `tests/test_quic_integration.py` — 4 candidates

- `tests/test_quic_integration.py::TestExtractTlsInfoQuicPath::test_quic_none_falls_through`
- `tests/test_quic_integration.py::TestExtractTlsInfoQuicPath::test_tcp_skips_quic`
- `tests/test_quic_integration.py::TestExtractTlsInfoQuicPath::test_udp_triggers_quic`
- `tests/test_quic_integration.py::TestQuicJA4Integration::test_quic_ja4_starts_with_q`

### `tests/test_quic_multipacket.py` — 5 candidates

- `tests/test_quic_multipacket.py::test_client_hello_from_crypto_fragments_returns_none_when_incomplete`
- `tests/test_quic_multipacket.py::test_ja4_fingerprinter_buffers_quic_fragments`
- `tests/test_quic_multipacket.py::test_reassemble_crypto_fragments_basic`
- `tests/test_quic_multipacket.py::test_reassemble_crypto_fragments_handles_duplicates`
- `tests/test_quic_multipacket.py::test_reassemble_crypto_fragments_out_of_order`

### `tests/test_quic_server_initial.py` — 10 candidates

- `tests/test_quic_server_initial.py::test_the_fragment_collector_drops_an_offset_past_the_limit`
- `tests/test_quic_server_initial.py::test_the_fragment_collector_keeps_a_fragment_that_fits`
- `tests/test_quic_server_initial.py::test_the_fragment_collector_stops_before_it_passes_the_limit`
- `tests/test_quic_server_initial.py::test_the_packet_end_reader_reads_the_length_field`
- `tests/test_quic_server_initial.py::test_the_packet_end_reader_returns_the_datagram_length_for_a_length_field_that_overruns`
- `tests/test_quic_server_initial.py::test_the_packet_end_reader_returns_the_datagram_length_for_a_truncated_header`
- `tests/test_quic_server_initial.py::test_the_server_hello_reader_rejects_an_empty_fragment_list`
- `tests/test_quic_server_initial.py::test_the_server_hello_reader_rejects_another_handshake_type`
- `tests/test_quic_server_initial.py::test_the_server_reader_rejects_a_short_header`
- `tests/test_quic_server_initial.py::test_the_server_reader_rejects_an_empty_connection_id`

### `tests/test_quic_utils.py` — 22 candidates

- `tests/test_quic_utils.py::TestDecodeVarint::test_1byte`
- `tests/test_quic_utils.py::TestDecodeVarint::test_2byte`
- `tests/test_quic_utils.py::TestDecodeVarint::test_4byte`
- `tests/test_quic_utils.py::TestDecodeVarint::test_zero`
- `tests/test_quic_utils.py::TestDeriveInitialSecrets::test_key_iv_hp_lengths`
- `tests/test_quic_utils.py::TestDeriveInitialSecrets::test_secret_lengths`
- `tests/test_quic_utils.py::TestExtractCryptoFrames::test_multiple_frames_reassembled`
- `tests/test_quic_utils.py::TestExtractCryptoFrames::test_no_crypto_returns_none`
- `tests/test_quic_utils.py::TestExtractCryptoFrames::test_padding_then_crypto`
- `tests/test_quic_utils.py::TestExtractCryptoFrames::test_single_crypto_frame`
- `tests/test_quic_utils.py::TestFindPnOffset::test_minimal_initial`
- `tests/test_quic_utils.py::TestHKDFExpandLabel::test_iv_length`
- `tests/test_quic_utils.py::TestHKDFExpandLabel::test_output_length`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_non_initial_type`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_short_header`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_too_short`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_v2_initial_type_not_rejected`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_v2_non_initial_rejected`
- `tests/test_quic_utils.py::TestParseQuicInitial::test_version_negotiation`
- `tests/test_quic_utils.py::TestParseQuicServerInitial::test_empty_client_dcid_returns_none`
- `tests/test_quic_utils.py::TestParseQuicServerInitial::test_short_header_returns_none`
- `tests/test_quic_utils.py::TestParseQuicServerInitial::test_too_short_returns_none`

### `tests/test_spec_validation.py` — 301 candidates

- `tests/test_spec_validation.py::TestConformanceIndex::test_the_connection_reader_reads_a_JA4L_connection_key`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_connection_reader_reads_a_JA4L_connection_key_of_two_IPv6_addresses`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_connection_reader_reads_a_JA4SSH_connection_key`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_index_holds_a_raw_form`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_index_holds_one_stream_for_both_directions`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_index_keeps_the_occurrence_counter_of_the_reference`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_index_names_the_stream_in_its_label`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_key_reader_reads_a_raw_form`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_key_reader_reads_the_occurrence_counter`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_key_reader_rejects_a_key_that_names_no_method`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_key_reader_reports_no_counter_on_a_plain_key`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_raw_method_map_names_only_a_key_the_reference_publishes`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_stream_identity_ignores_the_direction`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_stream_identity_separates_two_ports`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_suite_reports_both_JA4L_methods`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_value_reader_keeps_a_value_that_carries_no_prefix`
- `tests/test_spec_validation.py::TestConformanceIndex::test_the_value_reader_strips_the_JA4L_method_prefix`
- `tests/test_spec_validation.py::test_every_register_entry_matches_a_collected_case`
- `tests/test_spec_validation.py::test_every_register_entry_names_an_issue`
- `tests/test_spec_validation.py::test_the_collected_vector_set_equals_the_manifest`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream2:44403-JA4.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream2:44403-JA4_o.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream2:44403-JA4_r.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream2:44403-JA4_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream4:44405-JA4.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream4:44405-JA4_o.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream4:44405-JA4_r.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream4:44405-JA4_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream5:44406-JA4.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream5:44406-JA4_o.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream5:44406-JA4_r.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream5:44406-JA4_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream6:44407-JA4.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream6:44407-JA4_o.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream6:44407-JA4_r.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[alpn-condition.pcap-stream6:44407-JA4_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-stream0:57098-JA4H.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-stream0:57098-JA4H_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-stream0:57098-JA4X.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-stream0:57098-JA4X.2]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http-empty-useragent.pcap-stream0:57722-JA4H.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http-empty-useragent.pcap-stream0:57722-JA4H_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.10]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.11]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.12]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.13]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.14]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.15]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.2]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.3]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.4]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.5]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.6]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.7]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.8]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H.9]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.10]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.11]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.12]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.13]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.14]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.15]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.2]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.3]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.4]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.5]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.6]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.7]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.8]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4H_ro.9]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4X.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4X.2]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[http2-with-cookies.pcapng-stream0:58847-JA4X.3]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh-r.pcap-stream0:64980-JA4SSH.2]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh-r.pcap-stream1:46394-JA4SSH.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh-r.pcap-stream2:46396-JA4SSH.1]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh-scp-1050.pcap-stream0:49237-JA4SSH.3]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh-scp-1050.pcap-stream0:49237-JA4SSH.4]`
- `tests/test_spec_validation.py::test_the_produced_fingerprint_equals_the_reference[ssh2.pcapng-stream14:57377-JA4SSH.2]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4H_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[CVE-2018-6794.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[alpn-condition.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[browsers-x509.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[browsers-x509.pcapng-JA4S_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4H_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4_o]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[chrome-cloudflare-quic-with-secrets.pcapng-JA4_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcp.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[dhcpv6.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-erspan-vxlan.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-erspan-vxlan.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-erspan-vxlan.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-erspan-vxlan.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-erspan-vxlan.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-sample.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-sample.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-sample.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-sample.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[gre-sample.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http-empty-useragent.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http-empty-useragent.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http-empty-useragent.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http-empty-useragent.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1-with-cookies.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1-with-cookies.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1-with-cookies.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1-with-cookies.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http1.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http2-with-cookies.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http2-with-cookies.pcapng-JA4H_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http2-with-cookies.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[http2-with-cookies.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[https-connect.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[https-connect.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[https-connect.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[https-connect.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[https-connect.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[latest.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[latest.pcapng-JA4S_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[macos_tcp_flags.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[macos_tcp_flags.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[macos_tcp_flags.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-tls-handshake.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[quic-with-several-tls-frames.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[single-packets.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[socks4-https.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[socks4-https.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-r.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-r.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-r.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-r.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-scp-1050.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-scp-1050.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-scp-1050.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh-scp-1050.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-malformed.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-malformed.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-malformed.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-malformed.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-malformed.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-moloch-crash.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-moloch-crash.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-moloch-crash.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-moloch-crash.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2-moloch-crash.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4S_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4_o]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[ssh2.pcapng-JA4_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[sshv1.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[sshv1.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[sshv1.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[sshv1.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[sshv1.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tcpdump-geneve.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tcpdump-geneve.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tcpdump-geneve.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tcpdump-geneve.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tcpdump-geneve.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4S_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4_o]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-handshake.pcapng-JA4_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-non-ascii-alpn.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-non-ascii-alpn.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-non-ascii-alpn.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-non-ascii-alpn.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-non-ascii-alpn.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4_o]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls-sni.pcapng-JA4_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4L-C]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4L-S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls12.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4_o]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4_r]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[tls3.pcapng-JA4_ro]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4H]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4SSH]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4S]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4X]`
- `tests/test_spec_validation.py::test_the_produced_occurrence_keys_equal_the_reference[v6.pcap-JA4]`
- `tests/test_spec_validation.py::test_the_register_key_of_every_case_is_unique`
- `tests/test_spec_validation.py::test_the_suite_collects_at_least_one_vector`
- `tests/test_spec_validation.py::test_the_suite_collects_one_case_for_every_raw_key_of_the_reference`
- `tests/test_spec_validation.py::test_the_vector_is_readable[CVE-2018-6794.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[alpn-condition.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[badcurveball.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[browsers-x509.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[chrome-cloudflare-quic-with-secrets.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[dhcp.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[dhcpv6.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[gre-erspan-vxlan.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[gre-sample.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[http-empty-useragent.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[http1-with-cookies.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[http1.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[http2-with-cookies.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[https-connect.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[https3-301-get.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ipv6.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[latest.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[macos_tcp_flags.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[quic-tls-handshake.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[quic-with-several-tls-frames.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[single-packets.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[socks-https-example.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[socks4-https.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh-r.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh-scp-1050.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh2-malformed.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh2-moloch-crash.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[ssh2.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[sshv1.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tcpdump-geneve.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls-alpn-h2.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls-handshake.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls-non-ascii-alpn.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls-sni.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls12.pcap]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[tls3.pcapng]`
- `tests/test_spec_validation.py::test_the_vector_is_readable[v6.pcap]`

### `tests/test_tcp_stream.py` — 4 candidates

- `tests/test_tcp_stream.py::TestTCPStreamMaximumAge::test_the_default_maximum_age_passes_the_longest_gap_of_the_vectors`
- `tests/test_tcp_stream.py::TestTCPStreamMaximumAge::test_the_module_reads_no_wall_clock`
- `tests/test_tcp_stream.py::TestTCPStreamReassembler::test_a_trim_of_an_unknown_stream_does_nothing`
- `tests/test_tcp_stream.py::TestTCPStreamReassembler::test_the_base_sequence_of_an_unknown_stream_is_none`

### `tests/test_tunnels.py` — 6 candidates

- `tests/test_tunnels.py::TestInnermostLayer::test_the_helper_reads_an_address_layer_of_each_version`
- `tests/test_tunnels.py::TestInnermostLayer::test_the_helper_returns_none_when_the_packet_holds_no_such_layer`
- `tests/test_tunnels.py::TestInnermostLayer::test_the_helper_returns_the_inner_address_layer_of_a_tunnel`
- `tests/test_tunnels.py::TestInnermostLayer::test_the_helper_returns_the_inner_port_layer_of_a_tunnel`
- `tests/test_tunnels.py::TestInnermostLayer::test_the_helper_returns_the_only_address_layer_of_a_plain_packet`
- `tests/test_tunnels.py::TestRegisterTunnelDissectors::test_the_registration_returns_a_tuple_of_module_names`

### `tests/test_utils.py` — 36 candidates

- `tests/test_utils.py::TestGREASEDetection::test_all_16_grease_values`
- `tests/test_utils.py::TestGREASEDetection::test_common_extension_types_not_grease`
- `tests/test_utils.py::TestGREASEDetection::test_common_non_grease_cipher_suites`
- `tests/test_utils.py::TestGREASEDetection::test_grease_as_hex_string`
- `tests/test_utils.py::TestGREASEDetection::test_grease_edge_values`
- `tests/test_utils.py::TestGREASEDetection::test_grease_empty_string`
- `tests/test_utils.py::TestGREASEDetection::test_grease_invalid_types`
- `tests/test_utils.py::TestGREASEDetection::test_grease_none_and_zero`
- `tests/test_utils.py::TestGREASEDetection::test_non_grease_hex_string`
- `tests/test_utils.py::TestHTTPParsing::test_a_partial_method_name_can_become_an_http_request`
- `tests/test_utils.py::TestHTTPParsing::test_a_string_buffer_can_become_an_http_request`
- `tests/test_utils.py::TestHTTPParsing::test_a_tls_record_cannot_become_an_http_request`
- `tests/test_utils.py::TestHTTPParsing::test_an_empty_buffer_can_become_an_http_request`
- `tests/test_utils.py::TestHTTPParsing::test_extract_http_info_cookie_fields`
- `tests/test_utils.py::TestHTTPParsing::test_extract_http_info_headers_as_list`
- `tests/test_utils.py::TestHTTPParsing::test_extract_http_info_no_raw`
- `tests/test_utils.py::TestHTTPParsing::test_extract_http_info_referer`
- `tests/test_utils.py::TestHTTPParsing::test_is_http_request_false`
- `tests/test_utils.py::TestHTTPParsing::test_parse_empty_data`
- `tests/test_utils.py::TestHTTPParsing::test_parse_non_http_data`
- `tests/test_utils.py::TestOIDEncoding::test_different_oids_produce_different_hex`
- `tests/test_utils.py::TestOIDEncoding::test_oid_consistent`
- `tests/test_utils.py::TestSSHParsing::test_is_not_ssh`
- `tests/test_utils.py::TestSSHParsing::test_is_ssh_banner`
- `tests/test_utils.py::TestSSHParsing::test_is_ssh_kexinit_test_format`
- `tests/test_utils.py::TestSSHParsing::test_parse_empty_data`
- `tests/test_utils.py::TestSSHParsing::test_parse_short_data`
- `tests/test_utils.py::TestTLSParsing::test_extract_tls_info_no_raw`
- `tests/test_utils.py::TestTLSParsing::test_extract_tls_info_with_tls_info_attr`
- `tests/test_utils.py::TestTLSParsing::test_grease_in_ciphers_parsed`
- `tests/test_utils.py::TestTLSParsing::test_parse_client_hello_basic`
- `tests/test_utils.py::TestTLSParsing::test_parse_client_hello_without_sni`
- `tests/test_utils.py::TestTLSParsing::test_parse_empty_data`
- `tests/test_utils.py::TestTLSParsing::test_parse_non_handshake`
- `tests/test_utils.py::TestTLSParsing::test_parse_server_hello_rejects_a_truncated_hello_message`
- `tests/test_utils.py::TestTLSParsing::test_parse_too_short`

