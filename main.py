import os
import re
import sys
import json
import time
import uuid
import random
import struct
import asyncio
import logging
import threading
from datetime import datetime
from urllib.parse import unquote

import httpx
from flask import Flask, request, jsonify
from google_play_scraper import app as play_scraper
from protobuf_decoder.protobuf_decoder import Parser
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Pb2 import MajoRLoGinrEs_pb2, MajoRLoGinrEq_pb2, PorTs_pb2

DEV_NAME = "JAGWAR x STRAVEX"

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
log = logging.getLogger("jagwar")

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

REGION_LANG = {
    "BD": "bn", "IND": "hi", "PK": "ur", "SG": "en", "ID": "id",
    "ME": "ar", "VN": "vi", "TW": "zh", "CIS": "ru", "TH": "th",
    "EU": "en", "US": "en", "SAC": "es", "LK": "en", "BR": "pt"
}

DEFAULT_HEADERS = {
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.12f1',
    'X-GA-SV': '1789535859',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB55',
}


def HELLXenc_packet(payload, key, iv):
    raw = bytes.fromhex(payload) if isinstance(payload, str) else bytes(payload)
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if isinstance(iv, str):
        iv = bytes.fromhex(iv)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(raw, 16)).hex()


def HELLXdec_packet(payload, key, iv):
    raw = bytes.fromhex(payload) if isinstance(payload, str) else bytes(payload)
    if isinstance(key, str):
        key = bytes.fromhex(key)
    if isinstance(iv, str):
        iv = bytes.fromhex(iv)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw), 16).hex()


def HELLXenc_varint(n):
    if n < 0:
        return b''
    h = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        h.append(b)
        if not n:
            break
    return bytes(h)


def HELLXdec_varint(data, pos):
    res, shift = 0, 0
    while pos < len(data):
        b = data[pos]
        res |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7
    return 0, pos


def HELLXcreate_variant(f, v):
    return HELLXenc_varint((f << 3) | 0) + HELLXenc_varint(v)


def HELLXcreate_length(f, v):
    ev = v.encode('utf-8') if isinstance(v, str) else v
    return HELLXenc_varint((f << 3) | 2) + HELLXenc_varint(len(ev)) + ev


def HELLXcreate_proto(fields):
    packet = bytearray()
    for f, v in fields.items():
        if isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    packet.extend(HELLXcreate_length(f, HELLXcreate_proto(it)))
                elif isinstance(it, int):
                    packet.extend(HELLXcreate_variant(f, it))
                elif isinstance(it, (str, bytes)):
                    packet.extend(HELLXcreate_length(f, it))
        elif isinstance(v, dict):
            packet.extend(HELLXcreate_length(f, HELLXcreate_proto(v)))
        elif isinstance(v, int):
            packet.extend(HELLXcreate_variant(f, v))
        elif isinstance(v, (str, bytes)):
            packet.extend(HELLXcreate_length(f, v))
    return bytes(packet)


def HELLXdecode_proto(data):
    res_d, pos = {}, 0
    while pos < len(data):
        try:
            tag, pos = HELLXdec_varint(data, pos)
            if tag == 0:
                break
            fn, wt = tag >> 3, tag & 0x07
            key, val = str(fn), None
            if wt == 0:
                val, pos = HELLXdec_varint(data, pos)
            elif wt == 1:
                val = data[pos:pos + 8].hex()
                pos += 8
            elif wt == 2:
                length, pos = HELLXdec_varint(data, pos)
                chunk = data[pos:pos + length]
                pos += length
                try:
                    s = chunk.decode('utf-8')
                    if all(32 <= ord(c) <= 126 or ord(c) > 160 for c in s):
                        val = s.strip()
                    else:
                        raise Exception
                except Exception:
                    inner = HELLXdecode_proto(chunk)
                    val = inner if inner else chunk.hex()
            elif wt == 5:
                val = data[pos:pos + 4].hex()
                pos += 4
            else:
                pos += 1
                continue
            if val is not None:
                if key in res_d:
                    if not isinstance(res_d[key], list):
                        res_d[key] = [res_d[key]]
                    res_d[key].append(val)
                else:
                    res_d[key] = val
        except Exception:
            break
    return res_d


def HELLXgenerate_packet(proto_hex, opcode, key, iv):
    ep = HELLXenc_packet(proto_hex, key, iv)
    lh = hex(len(ep) // 2)[2:].zfill(2)
    if len(lh) == 2:
        header = opcode + "000000" + lh
    elif len(lh) == 3:
        header = opcode + "00000" + lh
    elif len(lh) == 4:
        header = opcode + "0000" + lh
    elif len(lh) == 5:
        header = opcode + "000" + lh
    else:
        header = opcode + lh
    return bytes.fromhex(header + ep)


def HELLXbuild_auth_startup(uid, token, timestamp, key, iv):
    uid_hex = hex(int(uid))[2:]
    ul = len(uid_hex)
    f = str(hex(timestamp))[2:]
    if len(f) == 1:
        f = "0" + f
    enc_tok = HELLXenc_packet(token.encode().hex(), key, iv)
    len_hex = hex(len(enc_tok) // 2)[2:].zfill(4)
    headers = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}.get(ul, '0000000')
    return f"0115{headers}{uid_hex}{f}0000{len_hex}{enc_tok}"


def HELLXbuild_chat_auth(uid, region_id, key, iv):
    fields = {1: 3, 2: {1: int(uid), 3: 'en', 4: str(region_id)}}
    return HELLXgenerate_packet(HELLXcreate_proto(fields).hex(), '1215', key, iv)


def get_randm_avatar():
    return random.choice([
        902000068, 902000016, 902000011, 902000084,
        902000085, 902000087, 902000106, 902045016
    ])


async def HELLXbuild_chat_message(uid, owner_uid, message, timestamp, key, iv, name="Bot"):
    fields = {
        1: 1,
        2: {
            1: uid,
            2: owner_uid,
            4: message,
            5: timestamp,
            7: 6,
            9: {
                1: name,
                2: get_randm_avatar(),
                3: 901000029,
                4: 330,
                5: 801043518,
                7: 2,
                10: 1,
                12: 0,
                13: {1: 2},
                14: {
                    1: uid,
                    2: 8,
                    3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"
                }
            },
            10: "en",
            13: {3: 1},
            14: ""
        }
    }
    return HELLXgenerate_packet(HELLXcreate_proto(fields).hex(), '1215', key, iv)


async def EnC_PacKeT(HeX, K, V):
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()


async def EnC_Vr(N):
    if N < 0:
        return b''
    H = []
    while True:
        B = N & 0x7F
        N >>= 7
        if N:
            B |= 0x80
        H.append(B)
        if not N:
            break
    return bytes(H)


async def CrEaTe_VarianT(f, v):
    return await EnC_Vr((f << 3) | 0) + await EnC_Vr(v)


async def CrEaTe_LenGTh(f, v):
    ev = v.encode() if isinstance(v, str) else v
    return await EnC_Vr((f << 3) | 2) + await EnC_Vr(len(ev)) + ev


async def CrEaTe_ProTo(fields):
    packet = bytearray()
    for f, v in fields.items():
        if isinstance(v, dict):
            packet.extend(await CrEaTe_LenGTh(f, await CrEaTe_ProTo(v)))
        elif isinstance(v, int):
            packet.extend(await CrEaTe_VarianT(f, v))
        elif isinstance(v, (str, bytes)):
            packet.extend(await CrEaTe_LenGTh(f, v))
    return packet


async def GeneRaTePk(Pk, N, K, V):
    PkEnc = await EnC_PacKeT(Pk, K, V)
    lh = hex(len(PkEnc) // 2)[2:]
    if len(lh) == 2:
        H = N + "000000"
    elif len(lh) == 3:
        H = N + "00000"
    elif len(lh) == 4:
        H = N + "0000"
    elif len(lh) == 5:
        H = N + "000"
    else:
        raise ValueError("Failed")
    return bytes.fromhex(H + lh + PkEnc)


async def ExiT(idT, K, V):
    fields = {1: 7, 2: {1: idT}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), '0515', K, V)


def build_ob55_online_auth(account_uid, token, kts, key, iv):
    enc_token = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(token.encode("utf-8"), 16))
    return (
        bytes.fromhex("830c")
        + int(account_uid).to_bytes(8, "big")
        + int(kts).to_bytes(4, "big")
        + len(enc_token).to_bytes(8, "big")
        + enc_token,
        enc_token
    )


async def JoinSq_original(code, K, V):
    skinz = {
        1: 4,
        2: {
            4: "\u0001\u0007\t\n\u000b\u0012\u0019 '",
            5: str(code),
            6: 6,
            8: 1,
            9: {
                1: "08FFF3BE903F27DF0203110111110000006B0003006800169194106F13CF106E4676251411010404dfe9e8b5ca3ca4f96a3119c00000004f03060301cacfa16d",
                2: 130,
                3: "tY_S\u0013\b\u0001M\u0002\u0000T\u0000\u0005\u000e\b\t\u0002\u0000\u0003U\u0003\u0001V\u000fR\u000e\tRQ\u0002\u0004\u0005US\u0003XS\u0005\u0001\u0002\u0011\u0001\u0002JuTAEN\u001e\u0002\u001c\u0002\u001f\u0013\b\u0003M\u001cDbz_Q@}p_QOgsC\u001dYVI\u0004UAAj_ga\u0004\u0012\u0000K\u001d\u0007_t\u0019b\bCx\u0002UeGat\u001fTTCBLER`\u0006\u0001\r\f\u0012\u0006\u0005N^^\u0002acH~r\u0004_\u0003RO|\u000bcd_@~`Rnqrgh\n\u0015\nL\\Nh\u0000~G\u000et\u0000eb]VQ\u0006t^F[ZIGxCdZD\u000b\u0011\u0002OA~LP@\u000fcSDyATQApaT^{|wa]\\\u0001E\u000f\u0013\nJfxve}\u0004J\u0003c{YL\u0007^^yDYQf\bhe\u0005_wg\r\u0010\u0007\bEHpX@||\u0002Z\\uTGyA\u0001JP\u0005t~VkTE\u0000J\\\u000b\u0013\nMr\u0018zTzK}qE]vnvwROuheYvwduvQ\r\u001a\u0005M\u0006z\u001dfXfzvHFc~dXUz}O\u001aB\u0005t\u0002i\u001co_\u0004\u0012\u0003\u0007J\u0006b\u0003\u000eqlfvbEstgu~wB\u0001v@`yI\u0002ZPx\f\u0014\u0003NR\u0002yBZvuD_cd\u0004q]lH]\u0007bD}pCe\t\u0004t\n",
                4: "w^_R",
                6: 11,
                7: "\u0014\u0004aqrg\u0015\u0013",
                8: "1.132.1",
                9: 3,
                10: 2,
                11: "\u0003bbSQ6wxegh9qAdV2KyoVleA17yPmYF+yTnOrl+JMknmppeUBe5ZsiHueP2mZZ4KOs6b2Ail1S9z3qIeU9hGFZ2M6PP39/zjIc/RFVPAkgDagySswMVmYaPhkzU5IqNPow2843fyQUz9xI10NdMhl1WiI4Y6wCXBotiUS9wSgujQ4j0fWXUyklCxBWo8r27hyoGSVrPdTPXFMnJJpPRRFFmWqc3fWvMg+BNfxSRJOZRSrkzG0nNvSIJ4uZB2pqAlHIPEYx7bI6zsgwUVDiLZJKTUTyuCGbOd1DegDUFfazFesTG1LJknT5WhgzCsrBIy+f2l+LeJe5DW7wEwNaHambM7ECXcJcLIhB9kJJsW0tFvXkk3HSdcQ8N1K6wjSKWhpkW0kV8Zrjj0jkhS/7AZ6T9GJRIA827YDtTorBvbx1UkXjYrqYI1nSa2GaMexGnqlurc5DE3v1R+mUBI9GqmjEPgTSYVBxyeCdQMHaMXGtspAhvkiO84ToU87sP45pylDEfFOVoc/rcmdzWeqlYPsv6txKRtIHcb0cO+MoVShoU8ZUVRDF3znbqzVrscPIfplBaa79lwvQqzRubLl9XY="
            },
            11: {1: "IDC4", 2: 281, 3: "ME"},
            13: "fr",
            16: "7OR\u0019",
            20: "\b\u0015",
            27: "\bH\u0010\u0003"
        }
    }
    return await GeneRaTePk((await CrEaTe_ProTo(skinz)).hex(), '0515', K, V)


async def MahirAccepted(uid, code, K, V, region):
    fields = {
        1: 4,
        2: {
            1: int(uid),
            3: int(uid),
            8: 1,
            9: {
                1: "08FBA33CFF105FDD02030A01111100000003000100020000B687046B0D6D2083467625141101030175a63c900e748c3f6a311e04000000ff00040202cacfa16d",
                2: 197,
                3: "735154531406054a035305025a0e50560f5100040250020f5e0401520653000303505e0d520302501500064d705548424e1f051a001e12040a441d45677f5a56477574565e4f6274451d585849005a4f456d5b64670c1400496d017842740c670100040069536e72586c02016e657e566b524403081500044d0d515b637f757c19095c7c510b00417f565e5e066f5b584d6e02400a160e4d58496d0177400e750763605c575d0f7d5f475e5f4c407f4b60534b0b140549751e66407a4860726e44400e6103557e515c646f43577106077b60051b0f4b4e474e58457e4f615c01406000051e0361516e7b67614e040102540c1609004a0e40730f62517f446a135179507e706850547f7e7a67795553597c0a1206445b456640046265725c4d505d446d50737b7c42035970486370645e0b12034d506f5c7a1c554f574b0e765a0f0a7364505203477569456c6c420f0a1604014b647149136c186f795f5d78755e550e7842545e53747b08705f7f5d0a14004a08666b5a5b5f00045c7f5e584d72584262705f56055c61475564790515004b76514178587f52797a0f077a070953507d7f4d784f794f667b4256081b0e4a75627d4778417a06717574747c4c78557b4b7a0a697f0e714573600a",
                4: "{Y_R",
                6: 13,
                7: "1c6f017306741513",
                8: "2.126.22",
                9: 2,
                10: 1,
                11: "036262535136784d584e38742b416456324b796f566c6537392f763672324d4773683377706379634f6b6b6f7447397934523930517432797246474c464c624c777a7747344d4d5257623146756d2b6556777a62597736743973492b787059612f55596e43465a59485235713348705830306c485a6f3632565145574e7145705866414c38734a754646575247386d376f5444566a4c484c576e714c52576f4e653236437a734c346a4144482b71694b55384d71476c5936546669544863716c487a345568463869396a365233366d49774b71746c36714f797568513854367945714b69742f45466d2b3636634b787649304f384d6c41385166454b6253467366477a2f30684e6a543873305369722f3962635a2f4679376c752f61632f366765704d415734566b442b36374f535756473665377a775a79312b797a42334b70632b7571782b577437414d39727761644439575765704570567849526d66654f5847627775787a68574b5664344c49586f415a364b387063647450627953575857455135706a542b653669365a2f6177444a3179356f774d5a534f64487262392b7877424a4d444f7848565a7a483372547a30314a316738517675466b656c3042433746473630683456427041494457487956684e794b4f5145507139467a4a6272686b316146306768766578512f6a2f484767426a5268675134645243372b477a5a687a2b77505967376454746f2b494d56363774642b54435653314234346b4148395a6d415872763758615941626477644e664f533170484875736b7336346f72463452534d3772656345417661484e61484854314c5545686e786a5a616d4d4f303d"
            },
            10: str(code),
            11: {1: "IDC3", 2: 84, 3: "ME"},
            13: "en",
            16: "374f5219",
            20: {1: 21},
            23: "a_1477547277882450725",
            27: {1: 2, 2: 8}
        }
    }
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), '0515', K, V)


def _pb_varint(n):
    if n < 0:
        n = (1 << 64) + n
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            break
    return bytes(out)


def _pb_tag(f, w):
    return _pb_varint((f << 3) | w)


def _pb_field(f, v):
    if isinstance(v, bool):
        v = int(v)
    if isinstance(v, int):
        return _pb_tag(f, 0) + _pb_varint(v)
    if isinstance(v, str):
        d = v.encode('utf-8')
        return _pb_tag(f, 2) + _pb_varint(len(d)) + d
    if isinstance(v, (bytes, bytearray)):
        d = bytes(v)
        return _pb_tag(f, 2) + _pb_varint(len(d)) + d
    return b""


async def aes_encrypt(payload, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, AES.block_size))


def get_proto_field(d, key, default=None):
    if not d or not isinstance(d, dict):
        return default
    if key in d:
        return d[key].get('data', default)
    if str(key) in d:
        return d[str(key)].get('data', default)
    return default


async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        fd = {"wire_type": result.wire_type}
        if result.wire_type in ("varint", "string", "bytes"):
            fd["data"] = result.data
        elif result.wire_type == "length_delimited":
            if hasattr(result.data, "results"):
                fd["data"] = await parse_results(result.data.results)
            elif isinstance(result.data, list):
                fd["data"] = await parse_results(result.data)
            else:
                fd["data"] = str(result.data)
        result_dict[str(result.field)] = fd
    return result_dict


_CACHED_APP_VERSION = None


async def get_playstore_version():
    global _CACHED_APP_VERSION
    if _CACHED_APP_VERSION:
        return _CACHED_APP_VERSION
    loop = asyncio.get_running_loop()
    try:
        res = await asyncio.wait_for(
            loop.run_in_executor(
                None, lambda: play_scraper('com.dts.freefireth', lang='hi', country='id')
            ),
            timeout=4.0
        )
        _CACHED_APP_VERSION = res.get("version", "1.134.21")
        return _CACHED_APP_VERSION
    except Exception:
        _CACHED_APP_VERSION = "1.134.21"
        return _CACHED_APP_VERSION


_CACHED_VER_CFG = {}


async def version_config(client_http, region="ME"):
    if region in _CACHED_VER_CFG:
        return _CACHED_VER_CFG[region]
    app_version = await get_playstore_version()
    lang = REGION_LANG.get(region, "ar")
    api_url = (
        f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
        f"&lang={lang}&device=android&channel=android&appstore=googleplay"
        f"&region={region}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0"
    )
    try:
        res = await client_http.get(api_url)
        data = res.json()
        cfg = (
            data.get("latest_release_version"),
            data.get("remote_version"),
            data.get("server_url"),
        )
        if cfg[0] and cfg[2]:
            _CACHED_VER_CFG[region] = cfg
        return cfg
    except Exception:
        return None


async def get_access_token(client_http, uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    for _ in range(2):
        try:
            r = await client_http.post(url, headers=hdrs, data=data)
            if r.status_code == 200:
                rd = r.json()
                return rd.get("open_id"), rd.get("access_token"), rd.get("platform", 4)
        except Exception:
            pass
        await asyncio.sleep(0.3)
    return None


async def build_majorlogin_payload(open_id, access_token, platform,
                                   client_version="1.134.21", region="ME", field_29=None):
    try:
        reg = (region or "ME").upper()
        proto = MajoRLoGinrEq_pb2.MajorLogin()
        proto.event_time = str(datetime.now())[:-7]
        proto.game_name = "free fire"
        proto.platform_id = 1
        proto.client_version = str(client_version or "1.134.21")
        proto.client_version_code = "2019121269"
        proto.system_software = "Android OS 13 / API-33 (TP1A.220624.014/eng.compil.20241021.212130)"
        proto.system_hardware = "Handheld"
        proto.device_type = "Handheld"
        proto.screen_width = 1600
        proto.screen_height = 720
        proto.screen_dpi = "300"
        proto.processor_details = "ARM64 FP ASIMD AES | 2000 | 8"
        proto.memory = 3743
        proto.gpu_renderer = "Mali-G52 MC2"
        proto.gpu_version = "OpenGL ES 3.2 v1.r26p0-01eac0.455662e55e7c7fb95a4b1db7e7af49a8"
        proto.unique_device_id = f"Google|{uuid.uuid4()}"
        proto.client_ip = f"106.219.{random.randint(1, 254)}.{random.randint(1, 254)}"
        proto.language = REGION_LANG.get(reg, "en")
        proto.open_id = str(open_id)
        proto.open_id_type = "4"
        proto.login_open_id_type = 1
        proto.access_token = str(access_token)
        proto.login_by = 3
        proto.platform_sdk_id = 1
        proto.origin_platform_type = "4"
        proto.primary_platform_type = "4"
        proto.reg_avatar = 1
        proto.channel_type = 3
        proto.telecom_operator = "airtel"
        proto.network_operator_a = "airtel"
        proto.network_type = "CarrierDataNetwork"
        proto.network_type_a = "4G"
        proto.cpu_type = 2
        proto.cpu_architecture = "64"
        proto.graphics_api = "OpenGLES2"
        proto.supported_astc_bitset = 4095
        proto.client_using_version = "7428b253defc164018c604a1ebbfebdf"
        proto.loading_time = 12556
        proto.release_channel = "android"
        proto.extra_info = "KqsHTxpGP5CwXDeHDi75pVSLPfiEigAhx+8r/es0KD31a2hBp9ZPNH1uhy+PLLpXhGjqWkGqVhZqw2BMbIBV/Hevo9X80/1swZ0nzuG9Gs6qO6HA"
        proto.android_engine_init_flag = 111207
        proto.if_push = 1
        proto.is_vpn = 0
        proto.memory_available.version = 55
        proto.memory_available.hidden_value = 81
        proto.external_storage_total = 47738
        proto.external_storage_available = 8234
        proto.internal_storage_total = 3504
        proto.internal_storage_available = 8527
        proto.game_disk_storage_total = 47938
        proto.game_disk_storage_available = 8234
        proto.external_sdcard_total_storage = 47738
        proto.external_sdcard_avail_storage = 8234
        proto.library_path = "/data/app/~~AckKiWUMLxHKcTatBB0dBA==/com.garena.game.ffi-PyAatSWUVmz6XVRiHvB2GA==/lib/arm64"
        proto.library_token = "dd9d4c174e0472d34b7fd34bd5924bc9|/data/app/~~AckKiWUMLxHKcTatBB0dBA==/com.garena.game.ffi-PyAatSWUVmz6XVRiHvB2GA==/base.apk"
        base_payload = proto.SerializeToString()
        extra = b""
        extra += _pb_field(25, "vivo V2152")
        extra += _pb_field(26, reg)
        if field_29:
            extra += _pb_field(29, str(field_29))
        extra += _pb_field(96, '{"cur_rate":null,"support_etc2":false}')
        extra += _pb_field(99, "4")
        extra += _pb_field(100, "4")
        extra += _pb_field(102, "")
        extra += _pb_field(104, 98784)
        extra += _pb_field(105, 1)
        extra += _pb_field(106, "https://dl-tata.freefireind.in/live/ABHotUpdates/|https://core-tata.freefireind.in/live/ABHotUpdates/|ac2c27398b1d5d95a4b6b6e04fa94066")
        extra += _pb_field(107, "1.1686d744a88f55b9")
        return await aes_encrypt(base_payload + extra, AES_KEY, AES_IV)
    except Exception as e:
        log.error(f"build_majorlogin_payload: {e}")
        return None


async def send_majorlogin(client_http, data, release_version, server_url):
    try:
        url = f"{server_url}MajorLogin" if server_url.endswith('/') else f"{server_url}/MajorLogin"
        req_headers = DEFAULT_HEADERS.copy()
        req_headers["ReleaseVersion"] = str(release_version)
        response = await client_http.post(url, headers=req_headers, data=data)
        if response.status_code != 200 or len(response.content) < 40:
            log.warning(f"MajorLogin HTTP {response.status_code}")
            return None
        res_proto = MajoRLoGinrEs_pb2.MajorLoginRes()
        try:
            res_proto.ParseFromString(response.content)
        except Exception:
            pass
        if not (res_proto.account_uid and res_proto.token):
            for offset in range(min(128, len(response.content))):
                try:
                    c = MajoRLoGinrEs_pb2.MajorLoginRes()
                    c.ParseFromString(response.content[offset:])
                    if c.account_uid and c.token:
                        res_proto = c
                        break
                except Exception:
                    pass
        parsed = Parser().parse(response.content.hex())
        dict_res = await parse_results(parsed)
        key_val = get_proto_field(dict_res, 22) or res_proto.key or AES_KEY
        iv_val = get_proto_field(dict_res, 23) or res_proto.iv or AES_IV
        if isinstance(key_val, str):
            try:
                key_val = bytes.fromhex(key_val)
            except Exception:
                pass
        if isinstance(iv_val, str):
            try:
                iv_val = bytes.fromhex(iv_val)
            except Exception:
                pass
        res_proto.key = key_val
        res_proto.iv = iv_val
        if not res_proto.url:
            res_proto.url = server_url
        return res_proto
    except Exception as e:
        log.error(f"MajorLogin error: {e}")
        return None


async def send_getlogin(client_http, data, base_url, token, release_version):
    try:
        url = f"{base_url.rstrip('/')}/GetLoginData"
        req_headers = DEFAULT_HEADERS.copy()
        req_headers["ReleaseVersion"] = str(release_version)
        req_headers['Authorization'] = f"Bearer {token}"
        response = await client_http.post(url, headers=req_headers, data=data)
        if response.status_code != 200:
            return None
        res_proto = PorTs_pb2.GetLoginData()
        try:
            res_proto.ParseFromString(response.content)
        except Exception:
            pass
        parsed = Parser().parse(response.content.hex())
        dict_res = await parse_results(parsed)
        return res_proto, dict_res
    except Exception as e:
        log.error(f"GetLoginData error: {e}")
        return None


async def do_login(uid, password, region_pref="ME"):
    async with httpx.AsyncClient(verify=False, timeout=7.0) as client_http:
        vc = await version_config(client_http, region_pref)
        if not vc:
            log.error("version_config failed")
            return None
        release_version, client_version, server_url = vc
        tg = await get_access_token(client_http, uid, password)
        if not tg:
            log.error(f"access_token failed for {uid}")
            return None
        open_id, access_token, platform = tg
        payload = await build_majorlogin_payload(open_id, access_token, platform, client_version, region_pref)
        if not payload:
            log.error("payload build failed")
            return None
        major_res = await send_majorlogin(client_http, payload, release_version, server_url)
        if not major_res or not major_res.account_uid:
            log.error(f"MajorLogin rejected for {uid}")
            return None
        gl = await send_getlogin(client_http, payload, major_res.url, major_res.token, release_version)
        if not gl:
            log.error(f"GetLoginData failed for {uid}")
            return None
        res_proto, dict_res = gl
        online_addr = res_proto.Online_IP_Port or get_proto_field(dict_res, 14, "0.0.0.0:0")
        online_ip, online_port = online_addr.split(":") if ':' in online_addr else ("0.0.0.0", "0")
        chat_addr = res_proto.AccountIP_Port or get_proto_field(dict_res, 32, online_addr)
        chat_ip, chat_port = chat_addr.split(":") if ':' in chat_addr else (online_ip, online_port)
        return {
            "bot_uid": str(major_res.account_uid),
            "token": major_res.token,
            "region": major_res.region or region_pref,
            "key": major_res.key or AES_KEY,
            "iv": major_res.iv or AES_IV,
            "timestamp": major_res.timestamp or int(time.time()),
            "online_ip": online_ip,
            "online_port": online_port,
            "chat_ip": chat_ip,
            "chat_port": chat_port,
            "account_name": res_proto.AccountName or "Unknown",
            "clan_id": res_proto.Clan_ID or 0,
            "clan_data": res_proto.Clan_Compiled_Data or "",
            "server_url": major_res.url,
            "login_data_raw": None,
        }


class SquadBot:
    def __init__(self, login, on_close=None):
        self.login = login
        self.uid = int(login["bot_uid"])
        self.token = login["token"]
        self.key, self.iv = login["key"], login["iv"]
        self.ts = int(login["timestamp"])
        self.region = (login.get("region") or "ME")
        self.name = login.get("account_name") or "Bot"
        self.on_close = on_close
        self.online_r = self.online_w = None
        self.chat_r = self.chat_w = None
        self._chat_buf = bytearray()
        self._online_buf = bytearray()
        self._tasks = []
        self.closed = False
        self.persistent = False
        self._last_invite = None
        self.owner_uid = None
        self.voice_region_id = None
        self.chat_region_id = None
        self._joined = asyncio.Event()

    def _spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks.append(t)
        return t

    async def connect(self):
        r = self.login
        self.chat_r, self.chat_w = await asyncio.wait_for(
            asyncio.open_connection(r["chat_ip"], int(r["chat_port"])), 6
        )
        self.chat_w.write(bytes.fromhex(
            HELLXbuild_auth_startup(self.uid, self.token, self.ts, self.key, self.iv)
        ))
        await self.chat_w.drain()
        self._spawn(self._chat_read_loop())
        self._spawn(self._keepalive(self.chat_w))
        await asyncio.sleep(0.3)
        auth, _ = build_ob55_online_auth(self.uid, self.token, self.ts, self.key, self.iv)
        self.online_r, self.online_w = await asyncio.wait_for(
            asyncio.open_connection(r["online_ip"], int(r["online_port"])), 6
        )
        self.online_w.write(auth)
        await self.online_w.drain()
        self._spawn(self._online_read_loop())
        self._spawn(self._keepalive(self.online_w))

    async def _keepalive(self, writer):
        try:
            while not self.closed and not writer.transport.is_closing():
                await asyncio.sleep(5)
                try:
                    writer.write(bytes.fromhex("0201"))
                    await writer.drain()
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    async def join(self, team_code, timeout=8):
        self._joined.clear()
        self.online_w.write(await JoinSq_original(str(team_code), self.key, self.iv))
        await self.online_w.drain()
        try:
            await asyncio.wait_for(self._joined.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def _on_joined(self, f5):
        self.voice_region_id = int(f5.get("17"))
        self.chat_region_id = int(self.voice_region_id / 256 + 0.5) * 256
        try:
            self.owner_uid = int(f5.get("1", self.uid))
        except Exception:
            self.owner_uid = self.uid
        self._joined.set()
        try:
            self.chat_w.write(HELLXbuild_chat_auth(self.owner_uid, str(self.chat_region_id), self.key, self.iv))
            await self.chat_w.drain()
        except Exception as e:
            log.warning(f"chat auth failed: {e}")

    async def leave(self):
        try:
            self.online_w.write(await ExiT(None, self.key, self.iv))
            await self.online_w.drain()
        except Exception:
            pass
        self._reset_team()

    def _reset_team(self):
        self.voice_region_id = self.chat_region_id = self.owner_uid = None
        self._last_invite = None
        self._joined.clear()

    @property
    def in_team(self):
        return bool(self.voice_region_id)

    async def _online_read_loop(self):
        try:
            while True:
                data = await self.online_r.read(16384)
                if not data:
                    break
                self._online_buf.extend(data)
                await self._drain_frames(self._online_buf, self._on_online_packet)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.warning(f"online loop: {e}")
        await self.close()

    async def _chat_read_loop(self):
        try:
            while True:
                data = await self.chat_r.read(16384)
                if not data:
                    break
                self._chat_buf.extend(data)
                await self._drain_frames(self._chat_buf, self._on_chat_packet)
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.warning(f"chat loop: {e}")

    @staticmethod
    async def _drain_frames(buf, handler):
        pos = 0
        while len(buf) - pos >= 5:
            length = struct.unpack(">I", buf[pos + 1:pos + 5])[0]
            if 0 < length < 200000:
                if pos + 5 + length > len(buf):
                    break
                payload = bytes(buf[pos + 5:pos + 5 + length])
                try:
                    pd = HELLXdecode_proto(payload)
                    if pd:
                        await handler(pd)
                except Exception as e:
                    log.warning(f"packet error: {e}")
                pos += 5 + length
            else:
                pos += 1
        if pos:
            del buf[:pos]

    async def _on_online_packet(self, pd):
        f5 = pd.get("5")
        if not isinstance(f5, dict):
            return
        code = f5.get("8")
        if isinstance(code, str) and "_" in code and code != self._last_invite \
                and self.persistent and not self.in_team:
            self._last_invite = code
            try:
                owner = int(f5.get("1", self.uid))
                self.online_w.write(await MahirAccepted(owner, code, self.key, self.iv, self.region))
                await self.online_w.drain()
            except Exception as e:
                log.warning(f"accept invite failed: {e}")
        if not self.voice_region_id and f5.get("17"):
            await self._on_joined(f5)

    async def _on_chat_packet(self, pd):
        return

    async def say(self, message):
        if not self.chat_w or self.chat_w.transport.is_closing():
            return
        try:
            owner = self.owner_uid or self.uid
            pkt = await HELLXbuild_chat_message(
                self.uid, owner, message, int(time.time()), self.key, self.iv, name=self.name
            )
            self.chat_w.write(pkt)
            await self.chat_w.drain()
        except Exception as e:
            log.warning(f"send failed: {e}")

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self._reset_team()
        for w in (self.online_w, self.chat_w):
            if w:
                try:
                    if w is self.online_w and not w.transport.is_closing():
                        w.write(await ExiT(None, self.key, self.iv))
                        await w.drain()
                except Exception:
                    pass
                try:
                    w.close()
                except Exception:
                    pass
        me = asyncio.current_task()
        for t in self._tasks:
            if t is not me and not t.done():
                t.cancel()
        if self.on_close:
            try:
                self.on_close(self)
            except Exception:
                pass


class AsyncLoop:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result()

    def start_background(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)


async_loop = AsyncLoop()


class AccountPool:
    def __init__(self, concurrency=12):
        self.accounts = []
        self.lock = asyncio.Lock()
        self.current_index = 0
        self.loading = False
        self.loaded = False
        self.concurrency = concurrency

    async def load_and_connect(self):
        if self.loading or self.loaded:
            return
        self.loading = True
        if not os.path.exists("accs.txt"):
            log.warning("accs.txt not found")
            self.loading = False
            self.loaded = True
            return
        with open("accs.txt", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if ":" in l]
        print(f"LOADED {len(lines)} ACCOUNTS FROM accs.txt")

        sem = asyncio.Semaphore(self.concurrency)

        async def _worker(line):
            async with sem:
                uid, password = line.split(":", 1)
                uid, password = uid.strip(), password.strip()
                try:
                    login = await do_login(uid, password, "ME")
                    if not login:
                        return
                    bot = SquadBot(login)
                    await bot.connect()
                    bot.persistent = True
                    async with self.lock:
                        self.accounts.append(bot)
                    print(f"ACCOUNT {uid} CONNECTED SUCCESFULLY .")
                except Exception as e:
                    log.error(f"account {uid} error: {e}")

        await asyncio.gather(*[_worker(line) for line in lines], return_exceptions=True)
        self.loading = False
        self.loaded = True

    async def get_next_bot(self):
        async with self.lock:
            if not self.accounts:
                return None
            bot = self.accounts[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.accounts)
            return bot

    async def wait_for_account(self, timeout=12):
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            bot = await self.get_next_bot()
            if bot:
                return bot
            if self.loaded and not self.accounts:
                return None
            await asyncio.sleep(0.5)
        return await self.get_next_bot()


account_pool = AccountPool(concurrency=12)
spam_tasks = {}


async def _spam_loop(bot, team_code, text, interval=1.1):
    key = str(team_code)
    try:
        while not bot.closed and bot.in_team:
            await bot.say(text)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning(f"spam loop error ({key}): {e}")
    finally:
        if spam_tasks.get(key) is asyncio.current_task():
            spam_tasks.pop(key, None)


async def run_tmc_spam(team_code, text, interval=1.1):
    team_code = str(team_code).strip()
    text = unquote(str(text or "")).strip()
    if not team_code.isdigit() or not text:
        return False, "Invalid team_code or empty text"

    bot = await account_pool.wait_for_account()
    if not bot:
        return False, "No connected accounts available yet"

    if not getattr(bot, "in_team", False):
        joined = await bot.join(team_code, timeout=8)
        if not joined:
            return False, "Failed to join team"
        await asyncio.sleep(0.5)
        print(f"SUCCESS JOINED TO {team_code}")

    old_task = spam_tasks.get(team_code)
    if old_task and not old_task.done():
        old_task.cancel()

    task = asyncio.create_task(_spam_loop(bot, team_code, text, interval=interval))
    spam_tasks[team_code] = task
    return True, "Joined and started spamming"


app = Flask(__name__)

# ÙØ¨Ø¯Ø£ ØªØ­ÙÙÙ Ø§ÙØ­Ø³Ø§Ø¨Ø§Øª ÙÙ Ø§ÙØ®ÙÙÙØ© ÙÙØ±Ø§Ù Ø¯ÙÙ ØªØ£Ø®ÙØ± Ø¥ÙÙØ§Ø¹ Ø§ÙØ³ÙØ±ÙØ±
async_loop.start_background(account_pool.load_and_connect())


def _parse_tmc_request():
    raw_tmc = request.args.get("tmc") or request.args.get("team_code") or ""
    raw_text = request.args.get("text") or ""

    full_path = request.full_path or ""
    match = re.search(r"/tmc=([^&/?]+)(?:&text=(.*))?$", full_path)
    if match:
        if not raw_tmc:
            raw_tmc = match.group(1) or ""
        if not raw_text and match.group(2) is not None:
            raw_text = match.group(2).rstrip("?")

    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        raw_tmc = body.get("tmc") or body.get("team_code") or raw_tmc
        raw_text = body.get("text") or raw_text

    return str(raw_tmc).strip(), raw_text


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "online",
        "accounts_loaded": len(account_pool.accounts),
        "loading": account_pool.loading,
        "usage": "/tmc?tmc=TEAM_CODE&text=MESSAGE",
        "stop_usage": "/stop_spam?tmc=TEAM_CODE",
        "DEV": DEV_NAME
    }), 200


@app.route("/tmc", methods=["GET", "POST"])
@app.route("/tmc=<path:rest>", methods=["GET", "POST"])
def tmc_route(rest=None):
    team_code, text = _parse_tmc_request()
    try:
        ok, msg = async_loop.run(run_tmc_spam(team_code, text, interval=1.1))
        return jsonify({
            "success": ok,
            "message": msg,
            "team_code": team_code,
            "DEV": DEV_NAME
        }), (200 if ok else 400)
    except Exception:
        log.exception("tmc_route error")
        return jsonify({
            "success": False,
            "message": "Internal server error",
            "team_code": team_code,
            "DEV": DEV_NAME
        }), 500


@app.route("/stop_spam", methods=["GET", "POST"])
def stop_spam():
    code = str(
        request.args.get("tmc")
        or request.args.get("team_code")
        or (request.get_json(silent=True) or {}).get("tmc")
        or ""
    ).strip()

    if code:
        t = spam_tasks.pop(code, None)
        if t and not t.done():
            t.cancel()
        return jsonify({"success": True, "message": f"Stopped spam for {code}", "DEV": DEV_NAME}), 200

    for t in list(spam_tasks.values()):
        if not t.done():
            t.cancel()
    spam_tasks.clear()
    return jsonify({"success": True, "message": "Stopped all spam loops", "DEV": DEV_NAME}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, threaded=True)
