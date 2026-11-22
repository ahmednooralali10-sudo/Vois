import os, re, sys, json, time, uuid, random, struct, shutil, asyncio, logging, threading
from datetime import datetime

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

REGION_LANG = {"BD": "bn", "IND": "hi", "PK": "ur", "SG": "en", "ID": "id",
               "ME": "ar", "VN": "vi", "TW": "zh", "CIS": "ru", "TH": "th",
               "EU": "en", "US": "en", "SAC": "es", "LK": "en", "BR": "pt"}

DEFAULT_HEADERS = {
    'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
    'Connection': 'Keep-Alive', 'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded', 'Expect': '100-continue',
    'X-Unity-Version': '2018.4.12f1', 'X-GA-SV': '1789535859',
    'X-GA': 'v1 1', 'ReleaseVersion': 'OB55',
}


def HELLXenc_packet(payload, key, iv):
    raw = bytes.fromhex(payload) if isinstance(payload, str) else bytes(payload)
    if isinstance(key, str): key = bytes.fromhex(key)
    if isinstance(iv, str): iv = bytes.fromhex(iv)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(raw, 16)).hex()


def HELLXdec_packet(payload, key, iv):
    raw = bytes.fromhex(payload) if isinstance(payload, str) else bytes(payload)
    if isinstance(key, str): key = bytes.fromhex(key)
    if isinstance(iv, str): iv = bytes.fromhex(iv)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(raw), 16).hex()


def HELLXenc_varint(n):
    if n < 0: return b''
    h = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        h.append(b)
        if not n: break
    return bytes(h)


def HELLXdec_varint(data, pos):
    res, shift = 0, 0
    while pos < len(data):
        b = data[pos]
        res |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80): return res, pos
        shift += 7
    return 0, pos


def HELLXcreate_variant(f, v): return HELLXenc_varint((f << 3) | 0) + HELLXenc_varint(v)


def HELLXcreate_length(f, v):
    ev = v.encode('utf-8') if isinstance(v, str) else v
    return HELLXenc_varint((f << 3) | 2) + HELLXenc_varint(len(ev)) + ev


def HELLXcreate_proto(fields):
    packet = bytearray()
    for f, v in fields.items():
        if isinstance(v, list):
            for it in v:
                if isinstance(it, dict): packet.extend(HELLXcreate_length(f, HELLXcreate_proto(it)))
                elif isinstance(it, int): packet.extend(HELLXcreate_variant(f, it))
                elif isinstance(it, (str, bytes)): packet.extend(HELLXcreate_length(f, it))
        elif isinstance(v, dict): packet.extend(HELLXcreate_length(f, HELLXcreate_proto(v)))
        elif isinstance(v, int): packet.extend(HELLXcreate_variant(f, v))
        elif isinstance(v, (str, bytes)): packet.extend(HELLXcreate_length(f, v))
    return bytes(packet)


def HELLXdecode_proto(data):
    res_d, pos = {}, 0
    while pos < len(data):
        try:
            tag, pos = HELLXdec_varint(data, pos)
            if tag == 0: break
            fn, wt = tag >> 3, tag & 0x07
            key, val = str(fn), None
            if wt == 0: val, pos = HELLXdec_varint(data, pos)
            elif wt == 1: val = data[pos:pos + 8].hex(); pos += 8
            elif wt == 2:
                length, pos = HELLXdec_varint(data, pos)
                chunk = data[pos:pos + length]; pos += length
                try:
                    s = chunk.decode('utf-8')
                    if all(32 <= ord(c) <= 126 or ord(c) > 160 for c in s): val = s.strip()
                    else: raise Exception
                except Exception:
                    inner = HELLXdecode_proto(chunk)
                    val = inner if inner else chunk.hex()
            elif wt == 5: val = data[pos:pos + 4].hex(); pos += 4
            else: pos += 1; continue
            if val is not None:
                if key in res_d:
                    if not isinstance(res_d[key], list): res_d[key] = [res_d[key]]
                    res_d[key].append(val)
                else: res_d[key] = val
        except Exception: break
    return res_d


def HELLXgenerate_packet(proto_hex, opcode, key, iv):
    ep = HELLXenc_packet(proto_hex, key, iv)
    lh = hex(len(ep) // 2)[2:].zfill(2)
    if len(lh) == 2: header = opcode + "000000" + lh
    elif len(lh) == 3: header = opcode + "00000" + lh
    elif len(lh) == 4: header = opcode + "0000" + lh
    elif len(lh) == 5: header = opcode + "000" + lh
    else: header = opcode + lh
    return bytes.fromhex(header + ep)


def HELLXbuild_auth_startup(uid, token, timestamp, key, iv):
    uid_hex = hex(int(uid))[2:]
    ul = len(uid_hex)
    f = str(hex(timestamp))[2:]
    if len(f) == 1: f = "0" + f
    enc_tok = HELLXenc_packet(token.encode().hex(), key, iv)
    len_hex = hex(len(enc_tok) // 2)[2:].zfill(4)
    headers = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}.get(ul, '0000000')
    return f"0115{headers}{uid_hex}{f}0000{len_hex}{enc_tok}"


def HELLXbuild_chat_auth(uid, region_id, key, iv):
    fields = {1: 3, 2: {1: int(uid), 3: 'en', 4: str(region_id)}}
    return HELLXgenerate_packet(HELLXcreate_proto(fields).hex(), '1215', key, iv)


def get_randm_avatar():
    return random.choice([902000068, 902000016, 902000011, 902000084,
                          902000085, 902000087, 902000106, 902045016])


async def HELLXbuild_chat_message(uid, owner_uid, message, timestamp, key, iv, name="Bot"):
    fields = {1: 1, 2: {1: uid, 2: owner_uid, 4: message, 5: timestamp, 7: 6,
             9: {1: name, 2: get_randm_avatar(), 3: 901000029, 4: 330,
                 5: 801043518, 7: 2, 10: 1, 12: 0, 13: {1: 2},
                 14: {1: uid, 2: 8, 3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006"}},
             10: "en", 13: {3: 1}, 14: ""}}
    return HELLXgenerate_packet(HELLXcreate_proto(fields).hex(), '1215', key, iv)


async def EnC_PacKeT(HeX, K, V):
    return AES.new(K, AES.MODE_CBC, V).encrypt(pad(bytes.fromhex(HeX), 16)).hex()


async def EnC_Vr(N):
    if N < 0: return b''
    H = []
    while True:
        B = N & 0x7F; N >>= 7
        if N: B |= 0x80
        H.append(B)
        if not N: break
    return bytes(H)


async def CrEaTe_VarianT(f, v): return await EnC_Vr((f << 3) | 0) + await EnC_Vr(v)


async def CrEaTe_LenGTh(f, v):
    ev = v.encode() if isinstance(v, str) else v
    return await EnC_Vr((f << 3) | 2) + await EnC_Vr(len(ev)) + ev


async def CrEaTe_ProTo(fields):
    packet = bytearray()
    for f, v in fields.items():
        if isinstance(v, dict): packet.extend(await CrEaTe_LenGTh(f, await CrEaTe_ProTo(v)))
        elif isinstance(v, int): packet.extend(await CrEaTe_VarianT(f, v))
        elif isinstance(v, (str, bytes)): packet.extend(await CrEaTe_LenGTh(f, v))
    return packet


async def GeneRaTePk(Pk, N, K, V):
    PkEnc = await EnC_PacKeT(Pk, K, V)
    lh = hex(len(PkEnc) // 2)[2:]
    if len(lh) == 2: H = N + "000000"
    elif len(lh) == 3: H = N + "00000"
    elif len(lh) == 4: H = N + "0000"
    elif len(lh) == 5: H = N + "000"
    else: raise ValueError("Failed")
    return bytes.fromhex(H + lh + PkEnc)


async def ExiT(idT, K, V):
    fields = {1: 7, 2: {1: idT}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), '0515', K, V)


def build_ob55_online_auth(account_uid, token, kts, key, iv):
    enc_token = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(token.encode("utf-8"), 16))
    return (bytes.fromhex("830c") + int(account_uid).to_bytes(8, "big") +
            int(kts).to_bytes(4, "big") + len(enc_token).to_bytes(8, "big") + enc_token, enc_token)


async def JoinSq_original(code, K, V):
    skinz = {1: 4, 2: {4: "\u0001\u0007\t\n\u000b\u0012\u0019 '", 5: str(code), 6: 6, 8: 1,
        9: {1: "08FFF3BE903F27DF0203110111110000006B0003006800169194106F13CF106E4676251411010404dfe9e8b5ca3ca4f96a3119c00000004f03060301cacfa16d", 2: 130,
            3: "tY_S\u0013\b\u0001M\u0002\u0000T\u0000\u0005\u000e\b\t\u0002\u0000\u0003U\u0003\u0001V\u000fR\u000e\tRQ\u0002\u0004\u0005US\u0003XS\u0005\u0001\u0002\u0011\u0001\u0002JuTAEN\u001e\u0002\u001c\u0002\u001f\u0013\b\u0003M\u001cDbz_Q@}p_QOgsC\u001dYVI\u0004UAAj_ga\u0004\u0012\u0000K\u001d\u0007_t\u0019b\bCx\u0002UeGat\u001fTTCBLER`\u0006\u0001\r\f\u0012\u0006\u0005N^^\u0002acH~r\u0004_\u0003RO|\u000bcd_@~`Rnqrgh\n\u0015\nL\\Nh\u0000~G\u000et\u0000eb]VQ\u0006t^F[ZIGxCdZD\u000b\u0011\u0002OA~LP@\u000fcSDyATQApaT^{|wa]\\\u0001E\u000f\u0013\nJfxve}\u0004J\u0003c{YL\u0007^^yDYQf\bhe\u0005_wg\r\u0010\u0007\bEHpX@||\u0002Z\\uTGyA\u0001JP\u0005t~VkTE\u0000J\\\u000b\u0013\nMr\u0018zTzK}qE]vnvwROuheYvwduvQ\r\u001a\u0005M\u0006z\u001dfXfzvHFc~dXUz}O\u001aB\u0005t\u0002i\u001co_\u0004\u0012\u0003\u0007J\u0006b\u0003\u000eqlfvbEstgu~wB\u0001v@`yI\u0002ZPx\f\u0014\u0003NR\u0002yBZvuD_cd\u0004q]lH]\u0007bD}pCe\t\u0004t\n",
            4: "w^_R", 6: 11, 7: "\u0014\u0004aqrg\u0015\u0013", 8: "1.132.1", 9: 3, 10: 2,
            11: "\u0003bbSQ6wxegh9qAdV2KyoVleA17yPmYF+yTnOrl+JMknmppeUBe5ZsiHueP2mZZ4KOs6b2Ail1S9z3qIeU9hGFZ2M6PP39/zjIc/RFVPAkgDagySswMVmYaPhkzU5IqNPow2843fyQUz9xI10NdMhl1WiI4Y6wCXBotiUS9wSgujQ4j0fWXUyklCxBWo8r27hyoGSVrPdTPXFMnJJpPRRFFmWqc3fWvMg+BNfxSRJOZRSrkzG0nNvSIJ4uZB2pqAlHIPEYx7bI6zsgwUVDiLZJKTUTyuCGbOd1DegDUFfazFesTG1LJknT5WhgzCsrBIy+f2l+LeJe5DW7wEwNaHambM7ECXcJcLIhB9kJJsW0tFvXkk3HSdcQ8N1K6wjSKWhpkW0kV8Zrjj0jkhS/7AZ6T9GJRIA827YDtTorBvbx1UkXjYrqYI1nSa2GaMexGnqlurc5DE3v1R+mUBI9GqmjEPgTSYVBxyeCdQMHaMXGtspAhvkiO84ToU87sP45pylDEfFOVoc/rcmdzWeqlYPsv6txKRtIHcb0cO+MoVShoU8ZUVRDF3znbqzVrscPIfplBaa79lwvQqzRubLl9XY="},
        11: {1: "IDC4", 2: 281, 3: "ME"}, 13: "fr", 16: "7OR\u0019", 20: "\b\u0015", 27: "\bH\u0010\u0003"}}
    return await GeneRaTePk((await CrEaTe_ProTo(skinz)).hex(), '0515', K, V)


async def MahirAccepted(uid, code, K, V, region):
    fields = {1: 4, 2: {1: int(uid), 3: int(uid), 8: 1,
        9: {1: "08FBA33CFF105FDD02030A01111100000003000100020000B687046B0D6D2083467625141101030175a63c900e748c3f6a311e04000000ff00040202cacfa16d", 2: 197,
            3: "735154531406054a035305025a0e50560f5100040250020f5e0401520653000303505e0d520302501500064d705548424e1f051a001e12040a441d45677f5a56477574565e4f6274451d585849005a4f456d5b64670c1400496d017842740c670100040069536e72586c02016e657e566b524403081500044d0d515b637f757c19095c7c510b00417f565e5e066f5b584d6e02400a160e4d58496d0177400e750763605c575d0f7d5f475e5f4c407f4b60534b0b140549751e66407a4860726e44400e6103557e515c646f43577106077b60051b0f4b4e474e58457e4f615c01406000051e0361516e7b67614e040102540c1609004a0e40730f62517f446a135179507e706850547f7e7a67795553597c0a1206445b456640046265725c4d505d446d50737b7c42035970486370645e0b12034d506f5c7a1c554f574b0e765a0f0a7364505203477569456c6c420f0a1604014b647149136c186f795f5d78755e550e7842545e53747b08705f7f5d0a14004a08666b5a5b5f00045c7f5e584d72584262705f56055c61475564790515004b76514178587f52797a0f077a070953507d7f4d784f794f667b4256081b0e4a75627d4778417a06717574747c4c78557b4b7a0a697f0e714573600a",
            4: "{Y_R", 6: 13, 7: "1c6f017306741513", 8: "2.126.22", 9: 2, 10: 1,
            11: "036262535136784d584e38742b416456324b796f566c6537392f763672324d4773683377706379634f6b6b6f7447397934523930517432797246474c464c624c777a7747344d4d5257623146756d2b6556777a62597736743973492b787059612f55596e43465a59485235713348705830306c485a6f3632565145574e7145705866414c38734a754646575247386d376f5444566a4c484c576e714c52576f4e653236437a734c346a4144482b71694b55384d71476c5936546669544863716c487a345568463869396a365233366d49774b71746c36714f797568513854367945714b69742f45466d2b3636634b787649304f384d6c41385166454b6253467366477a2f30684e6a543873305369722f3962635a2f4679376c752f61632f366765704d415734566b442b36374f535756473665377a775a79312b797a42334b70632b7571782b577437414d39727761644439575765704570567849526d66654f5847627775787a68574b5664344c49586f415a364b387063647450627953575857455135706a542b653669365a2f6177444a3179356f774d5a534f64487262392b7877424a4d444f7848565a7a483372547a30314a316738517675466b656c3042433746473630683456427041494457487956684e794b4f5145507139467a4a6272686b316146306768766578512f6a2f484767426a5268675134645243372b477a5a687a2b77505967376454746f2b494d56363774642b54435653314234346b4148395a6d415872763758615941626477644e664f533170484875736b7336346f72463452534d3772656345417661484e61484854314c5545686e786a5a616d4d4f303d"},
        10: str(code), 11: {1: "IDC3", 2: 84, 3: "ME"}, 13: "en", 16: "374f5219",
        20: {1: 21}, 23: "a_1477547277882450725", 27: {1: 2, 2: 8}}}
    return await GeneRaTePk((await CrEaTe_ProTo(fields)).hex(), '0515', K, V)


def _vread_varint(data, pos): return HELLXdec_varint(data, pos)


def _vtry_read_string_field(data, pos, efn):
    if pos >= len(data): return None, pos
    tb, p = _vread_varint(data, pos)
    fn, wt = tb >> 3, tb & 0x7
    if fn != efn or wt != 2: return None, pos
    if p >= len(data): return None, pos
    length, p = _vread_varint(data, p)
    if length <= 0 or p + length > len(data): return None, pos
    raw = data[p:p + length]
    try: return raw.decode('utf-8'), p + length
    except Exception: return None, pos


def _vscan_idc_entries(data):
    entries, seen, pos = [], set(), 0
    while pos < len(data) - 6:
        if data[pos] != 0x0a: pos += 1; continue
        region, p2 = _vtry_read_string_field(data, pos, 1)
        if region is None or not region.isalpha() or len(region) < 2: pos += 1; continue
        idc_name, p3 = _vtry_read_string_field(data, p2, 2)
        if idc_name is None or len(idc_name) < 2: pos += 1; continue
        ip_port, p4 = _vtry_read_string_field(data, p3, 3)
        if ip_port is None or ':' not in ip_port: pos += 1; continue
        parts = ip_port.split(':')
        if len(parts) != 2 or not parts[1].isdigit(): pos += 1; continue
        if ip_port not in seen:
            seen.add(ip_port); entries.append({"region": region, "idc": idc_name, "ip_port": ip_port})
        pos = p4
    return entries


def _vscan_field10_chunks(data, seen_offsets=None):
    if seen_offsets is None: seen_offsets = set()
    results, pos = [], 0
    while pos < len(data):
        if data[pos] != 0x52: pos += 1; continue
        try: length, ds = _vread_varint(data, pos + 1)
        except Exception: pos += 1; continue
        if length <= 0 or ds + length > len(data): pos += 1; continue
        chunk, ep = data[ds:ds + length], ds + length
        ak = (pos, ep)
        if ak not in seen_offsets:
            seen_offsets.add(ak); results.append(chunk)
            results.extend(_vscan_field10_chunks(chunk, seen_offsets))
        pos = ep
    return results


def _vdecode_idc_message(chunk):
    fields, pos = {}, 0
    while pos < len(chunk):
        try:
            tb, pos = _vread_varint(chunk, pos)
            fn, wt = tb >> 3, tb & 0x7
            if fn == 0 or wt not in (0, 1, 2, 5): break
            if wt == 0: val, pos = _vread_varint(chunk, pos); fields[fn] = val
            elif wt == 2:
                length, pos = _vread_varint(chunk, pos)
                rv = chunk[pos:pos + length]; pos += length
                try: fields[fn] = rv.decode('utf-8')
                except Exception: fields[fn] = rv
            elif wt == 1: pos += 8
            elif wt == 5: pos += 4
        except Exception: break
    if 1 in fields and 2 in fields and 3 in fields:
        r = fields[1] if isinstance(fields[1], str) else None
        i = fields[2] if isinstance(fields[2], str) else None
        p = fields[3] if isinstance(fields[3], str) else None
        if r and i and p and ':' in p: return {"region": r, "idc": i, "ip_port": p}
    return None


def _vextract_webrtc_block(chunk):
    for m in (b'ff.sdk.grtc', b'ff.rtc.grtc', b'ff.dr.grtc'):
        idx = chunk.find(m)
        if idx != -1: break
    else:
        idx = chunk.find(b'garenanow')
        if idx == -1: return None
        while idx > 0 and chunk[idx - 1] in b'abcdefghijklmnopqrstuvwxyz0123456789.-': idx -= 1
    ALLOWED = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-;,_/')
    end = idx
    while end < len(chunk) and chunk[end] in ALLOWED: end += 1
    bs = chunk[idx:end].decode('utf-8', errors='ignore')
    rp = []
    for seg in bs.split(';'):
        for sub in seg.split(','):
            p = sub.strip()
            if p: rp.append(p)
    doms = [p for p in rp if 'garenanow' in p or 'grtc' in p]
    def isv(s):
        sg = s.split('.')
        return len(sg) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 for x in sg)
    ips = [p for p in rp if p not in doms and isv(p)]
    if not doms and not ips: return None
    return {"description": "WebRTC Fallback", "domains": doms, "ips": ips}


def HELLXextract_garena_voice_data(raw_bytes):
    result = {"idc_servers": [], "webrtc": None}
    seen, added = set(), False
    for chunk in _vscan_field10_chunks(raw_bytes):
        idc = _vdecode_idc_message(chunk)
        if idc is not None:
            if idc['ip_port'] not in seen:
                seen.add(idc['ip_port']); result["idc_servers"].append(idc)
            continue
        if not added and (b'ff.rtc.grtc' in chunk or b'garenanow' in chunk):
            w = _vextract_webrtc_block(chunk)
            if w: result["webrtc"] = w; added = True
    if not result["idc_servers"]:
        for e in _vscan_idc_entries(raw_bytes):
            if e['ip_port'] not in seen:
                seen.add(e['ip_port']); result["idc_servers"].append(e)
    return result


def HELLXlog(tag, msg): log.info(f"{tag} = > {msg}")


_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(_CACHE_DIR, exist_ok=True)

_VOICE_BASE_HEX = ('0a8e01' '0811100b180122' '04534f4e59' '2a013930cc80868c02' '3a0b61726d65616269'
                   '2d763761' '4200' '4a2438323934386166322d313737392d346438372d613864352d356237363962376365623934'
                   '522a464644353846423446373646363438433241354532314542434641334141453831423443394237443937'
                   '5a05766f696365' '62075851' '2d42453432' '6802' '720471636f6d' '100b')
_STEP1_FIXED128_HEX = ('69839458c071310bbc7e2eede4101c55f0e8c682102c5b100c79'
                       '291ae9800ad21d16f7a4e484d4c09f5960f58d00a576128a7bad'
                       '036fe886b369e6e2e07ad339be2d93f40eb37e640790972809ea'
                       '078b24540912ca6dd3f54183ac721db4c50cd3703941'
                       '9f467a430d9429eeee04ead8b83073e54e45a51e0d33b9b273fd2942')


def HELLXbuild_voice_step1(uid, region_id):
    base = bytearray(bytes.fromhex(_VOICE_BASE_HEX)); base[4] = 0x00
    payload = bytes(base) + b'\x12\x80\x01' + bytes.fromhex(_STEP1_FIXED128_HEX) + b'\x18\x01\x20\x06\x38\x01'
    return struct.pack('>I', len(payload)) + payload


def HELLXbuild_voice_auth(uid, region_id, voice_port, region_prefix="EUROPE"):
    base = bytearray(bytes.fromhex(_VOICE_BASE_HEX)); base[4] = 0x07
    device_id = "FFD58FB4F76F648C2A5E21EBCFA3AAE81B4C9B7D97"
    f2 = (device_id + f"{region_prefix}_{region_id}").encode()
    ub = uid.encode()
    fl = len(f2)
    flv = bytes([fl]) if fl < 128 else bytes([0x80 | (fl & 0x7F), fl >> 7])
    payload = (bytes(base) + b'\x12' + flv + f2 + bytes.fromhex('20052801' '30d008' '380040005001') +
               b'\x5a' + bytes([len(ub)]) + ub + bytes.fromhex('60007000800101'))
    return struct.pack('>I', len(payload)) + payload


def HELLXbuild_voice_ping(uid, region_id, voice_port, session_id=0x0b):
    base = bytearray(bytes.fromhex(_VOICE_BASE_HEX)); base[4] = 0x09
    payload = bytes(base[:-2]) + b'\x10' + HELLXenc_varint(session_id)
    return struct.pack('>I', len(payload)) + payload


def HELLXbuild_voice_custom(uid, region_id, uuid="f687ba460e-9b6b8bc39",
                            device_id="F76F648CCFA3AAE897", mcu_ip="0.0.0.0", region_prefix="EUROPE"):
    uid_last3 = uid.zfill(11)[-3:].encode()
    region_str = f"{region_prefix}_{region_id}".encode()
    ts = int(time.time()) & 0xFFFFFFFF
    pkt = bytearray(bytes.fromhex('feffffff04b50001'))
    pkt.extend(b'\x00\x24'); pkt.extend(uuid.encode()); pkt.append(0)
    pkt.extend(b'\x00\x2a'); pkt.extend(device_id.encode()); pkt.append(0)
    pkt.extend(b'\x00\x1a'); pkt.extend(region_str); pkt.append(0)
    pkt.extend(b'\x00\x0b'); pkt.extend(uid_last3); pkt.extend(b'\x00\x00\x00\x00')
    pkt.extend(b'\x28\x2e\x30\x00'); pkt.append(0x07)
    pkt.extend(b"0.0.0.0"); pkt.extend(b'\x00'); pkt.append(0x0d)
    pkt.extend(mcu_ip.encode()); pkt.extend(b'\x00')
    pkt.extend(b'\x17\x76'); pkt.extend(struct.pack('>I', ts)); pkt.extend(b'\x00\x00\x00\x00')
    return struct.pack('>I', len(pkt)) + bytes(pkt)


def HELLXbuild_voice_redirect(uid, region_id, region_prefix="EUROPE", ext_region="de"):
    device_id = "FFD58FB4F76F648C2A5E21EBCFA3AAE81B4C9B7D97"
    f1 = (device_id + f"{region_prefix}_{region_id}").encode()
    base = bytes.fromhex(_VOICE_BASE_HEX)
    inner = bytearray(base[3:3 + 142]); inner[1] = 0x11
    eb = ext_region.encode()
    payload = bytearray()
    payload.append(0x0a); payload.append(len(f1)); payload.extend(f1)
    payload.append(0x12); payload.append(0x8e); payload.append(0x01); payload.extend(inner)
    payload.append(0x18); payload.append(0x02)
    payload.append(0x22); payload.append(len(eb)); payload.extend(eb)
    return struct.pack('>I', len(payload)) + bytes(payload)


def _yt_dlp_command(): return [sys.executable, "-m", "yt_dlp"]


def _ffmpeg_executable():
    exe = shutil.which("ffmpeg")
    if exe: return exe
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception as exc:
        raise FileNotFoundError("ffmpeg is not installed.") from exc


def _ogg_opus_frames_bytes(data):
    _, frames = _parse_ogg_buf(data, drain_all=True)
    yield from frames


def _parse_ogg_buf(buf, drain_all=False):
    frames = []
    while True:
        pos = buf.find(b'OggS')
        if pos == -1:
            buf = buf[-3:] if len(buf) >= 3 else buf; break
        if len(buf) < pos + 27: break
        n_segs = buf[pos + 26]
        header_end = pos + 27 + n_segs
        if len(buf) < header_end: break
        seg_table = buf[pos + 27: header_end]
        page_size = sum(seg_table)
        if len(buf) < header_end + page_size: break
        page_data = buf[header_end: header_end + page_size]
        buf = buf[header_end + page_size:]
        if page_data[:8] in (b'OpusHead', b'OpusTags'): continue
        off = 0
        for s in seg_table:
            frame = page_data[off: off + s]; off += s
            if len(frame) >= 4: frames.append(frame)
    return buf, frames


class VoicePlayer:
    def __init__(self, uid, region_prefix="ME", ext_region="ME", send_chat=None):
        self.uid = uid
        self.region_prefix = region_prefix
        self.ext_region = ext_region
        self._send_chat = send_chat
        self.voice_region_id = None
        self.voice_port = None
        self.voice_session_ts = None
        self._sdk_verify_domain = "ff.rtc.grtc.garenanow.com"
        self._voice_f5 = 0
        self._voice_f3 = 0x13e6
        self._voice_writer = None
        self._voice_reader = None
        self._voice_ping_task = None
        self._voice_connect_task = None
        self._voice_ip = None
        self._voice_port = None
        self._udp_task = None
        self._voice_ssrc_refresh = False
        self.opus_bitrate = 96000
        self._current_url = None
        self._current_ogg = None
        self._track_title = ""
        self._track_channel = ""
        self._track_total_frames = 0
        self._track_current_frame = 0
        self._progress_task = None
        self._stopped_frame = 0
        self._volume = 100
        self._lyrics_enabled = False
        self._lyrics_data = []
        self._lyrics_task = None

    async def _send_chat_message(self, message):
        if self._send_chat:
            try: await self._send_chat(message)
            except Exception: pass

    def configure(self, login_data_raw=None, region=None):
        if login_data_raw:
            try:
                vd = HELLXextract_garena_voice_data(login_data_raw)
                for entry in vd["idc_servers"]:
                    ip, port = entry["ip_port"].split(":")
                    if entry["idc"] == "IDC2": self.voice_port = int(port)
                    elif self.voice_port is None: self.voice_port = int(port)
                w = vd.get("webrtc")
                if w and w.get("domains"): self._sdk_verify_domain = w["domains"][0]
            except Exception as e:
                HELLXlog("VOICE", f"configure failed: {e}")
        if region and isinstance(region, str) and region.isalpha():
            self.region_prefix = region.upper()
            m = {'EUROPE': 'eu', 'VN': 'vn', 'SA': 'sa', 'BR': 'br', 'ID': 'id',
                 'TW': 'tw', 'TH': 'th', 'SG': 'sg', 'ME': 'me', 'IND': 'in',
                 'NA': 'na', 'LATAM': 'la'}
            self.ext_region = m.get(self.region_prefix, self.region_prefix.lower()[:2])

    def start(self, voice_region_id):
        self.voice_region_id = int(voice_region_id)
        if not self._voice_connect_task or self._voice_connect_task.done():
            self._voice_connect_task = asyncio.create_task(self._voice_connect())

    async def play(self, url): await self._play_yt(url)

    def stop(self):
        for t in (self._udp_task, self._progress_task, self._voice_ping_task, self._voice_connect_task):
            if t and not t.done(): t.cancel()
        w = self._voice_writer
        if w:
            try: w.close()
            except Exception: pass
        self._voice_ip = self._voice_port = None

    async def _voice_connect(self):
        if not self.voice_region_id:
            HELLXlog("VOICE", "ERROR: No region_id"); return
        self._voice_f5 = 0
        self._voice_f3 = 0x13e6
        import aiohttp as _aiohttp

        async def _read_voice_frame(reader, timeout):
            header = await asyncio.wait_for(reader.readexactly(4), timeout)
            fl = struct.unpack('>I', header)[0]
            if fl <= 0 or fl > 65536: raise ValueError(f"invalid voice frame length: {fl}")
            return await asyncio.wait_for(reader.readexactly(fl), timeout)

        sdk_token = None
        redirect_ip, redirect_port = None, None
        SDK_VERIFY_URL = f"https://{self._sdk_verify_domain}/sdk/sdk_verify"
        _SDK_VERIFY_PAYLOAD = bytes.fromhex(
            '0a8e010800100b180122074f6e65506c75732a013930cc80868c023a0961726d3634'
            '2d76386142004a2439313864346563382d383733332d343930622d626334362d643132'
            '666139396337383238522a464644353846423446373646363438433241354532314542'
            '4346413341414538314234433942374439375a05766f69636562064e45323231316802'
            '720471636f6d12800160ad4251d2f821e2701e5e1d8b607d2b34dcb0c512300ac3e5839'
            '6155780dc64686b20d05581c038ae28539fc3bc21ced330e31721e18e6c626972829f'
            '6878cb8ec7d95f2f7391bd25f9d7296f09f56f9bc5bccabaf10f09b58c39dc02c08995'
            'd6abe727d93bcea4123da86ad42f6500fa68e74ddc2ed2cb7af0aadd22d2ec93180120'
            '063800')

        def _parse_sdk_response(data):
            nonlocal sdk_token, redirect_ip, redirect_port
            if len(data) < 4: return
            _vproto = HELLXdecode_proto(data)
            _f5 = _vproto.get('5')
            _cands = _f5 if isinstance(_f5, list) else ([_f5] if _f5 else [])
            for _r in _cands:
                if isinstance(_r, bytes): _r = HELLXdecode_proto(_r)
                if isinstance(_r, dict):
                    _rip = _r.get('1'); _rport = _r.get('2')
                    if isinstance(_rip, str) and '.' in _rip and _rport:
                        redirect_ip = _rip; redirect_port = int(_rport)
                        HELLXlog("VOICE", f"SDK verify redirect: {redirect_ip}:{redirect_port}")
                        break
            if not redirect_ip:
                m_ip = re.search(rb'([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', data)
                if m_ip: redirect_ip = m_ip.group(1).decode()
            _pos = 0
            while _pos < len(data) - 2:
                if data[_pos] == 0x12:
                    _p2 = _pos + 1; _vlen = 0; _shift = 0
                    while _p2 < len(data):
                        _b = data[_p2]; _vlen |= (_b & 0x7F) << _shift; _p2 += 1; _shift += 7
                        if not (_b & 0x80): break
                    if _vlen == 128 and _p2 + 128 <= len(data):
                        sdk_token = data[_p2:_p2 + 128]; break
                _pos += 1

        try:
            _ssl_ctx = __import__('ssl').create_default_context()
            _ssl_ctx.check_hostname = False
            _ssl_ctx.verify_mode = __import__('ssl').CERT_NONE
            async with _aiohttp.ClientSession() as _sess:
                async with _sess.post(SDK_VERIFY_URL, data=_SDK_VERIFY_PAYLOAD,
                    headers={"Host": self._sdk_verify_domain, "Accept": "*/*",
                             "Accept-Encoding": "identity",
                             "Content-Type": "application/x-www-form-urlencoded",
                             "Content-Length": str(len(_SDK_VERIFY_PAYLOAD))},
                    ssl=_ssl_ctx, timeout=_aiohttp.ClientTimeout(total=8)) as _resp:
                    _rbody = await _resp.read()
                    HELLXlog("VOICE", f"SDK verify HTTPS: status={_resp.status} len={len(_rbody)}")
                    if _resp.status == 200 and len(_rbody) > 4: _parse_sdk_response(_rbody)
        except Exception as e:
            HELLXlog("VOICE", f"SDK verify HTTPS failed: {e}")

        if not redirect_ip:
            try:
                import socket as _sock
                _infos = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: _sock.getaddrinfo(self._sdk_verify_domain, 8012, _sock.AF_INET))
                _tcp_ips = list(dict.fromkeys(info[4][0] for info in _infos))
                _tcp_pkt = struct.pack('>I', len(_SDK_VERIFY_PAYLOAD)) + _SDK_VERIFY_PAYLOAD
                for _tip in _tcp_ips:
                    try:
                        _tr, _tw = await asyncio.wait_for(asyncio.open_connection(_tip, 8012), timeout=5.0)
                        _tw.write(_tcp_pkt); await _tw.drain()
                        _tbody = b""
                        try:
                            _chunk = await asyncio.wait_for(_tr.read(65536), timeout=8.0)
                            if _chunk: _tbody = _chunk
                        except asyncio.TimeoutError: pass
                        try: _tw.close()
                        except Exception: pass
                        if _tbody:
                            _parse_sdk_response(_tbody[4:] if len(_tbody) > 4 else _tbody)
                            if redirect_ip: break
                    except Exception: pass
            except Exception as e:
                HELLXlog("VOICE", f"SDK verify TCP fallback failed: {e}")

        if not redirect_ip or not redirect_port:
            HELLXlog("VOICE", "ERROR: No redirect from SDK verify"); return
        try:
            r2, w2 = await asyncio.wait_for(asyncio.open_connection(redirect_ip, redirect_port), timeout=5.0)
        except Exception as e:
            HELLXlog("VOICE", f"Step2 failed: {e}"); return
        w2.write(HELLXbuild_voice_redirect(self.uid, self.voice_region_id, self.region_prefix, self.ext_region))
        await w2.drain()
        voice_ip, voice_port = None, None
        try:
            h2 = await asyncio.wait_for(r2.readexactly(4), timeout=5.0)
            rl = struct.unpack('>I', h2)[0]
            if 0 < rl <= 65536:
                resp2 = h2 + await asyncio.wait_for(r2.readexactly(rl), timeout=5.0)
                proto = HELLXdecode_proto(resp2[4:])
                ip_val = proto.get('1'); port_val = proto.get('2')
                if isinstance(ip_val, str) and '.' in ip_val: voice_ip = ip_val
                if isinstance(port_val, int): voice_port = port_val
        except asyncio.TimeoutError: pass
        try: w2.close()
        except Exception: pass
        if not voice_ip or not voice_port:
            HELLXlog("VOICE", "ERROR: No voice IP from redirect"); return
        try:
            r3, w3 = await asyncio.wait_for(asyncio.open_connection(voice_ip, voice_port), timeout=5.0)
        except Exception as e:
            HELLXlog("VOICE", f"Step3 failed: {e}"); return
        self._voice_writer = w3; self._voice_reader = r3
        auth3 = HELLXbuild_voice_auth(self.uid, self.voice_region_id, voice_port, self.region_prefix)
        w3.write(auth3[:4]); await w3.drain()
        w3.write(auth3[4:]); await w3.drain()
        try:
            resp3 = await _read_voice_frame(r3, 3.0)
            if resp3:
                _p = HELLXdecode_proto(resp3)
                self._voice_f3 = int(_p.get('3', 0x13e6))
                f5_value = _p.get('5', _p.get('13', 0))
                if isinstance(f5_value, dict): f5_value = f5_value.get('1', 0)
                if isinstance(f5_value, list): f5_value = f5_value[0] if f5_value else 0
                self._voice_f5 = int(f5_value) & 0xFFFFFFFF
        except (asyncio.TimeoutError, TypeError, ValueError): pass
        if self._voice_f5 == 0:
            HELLXlog("VOICE", "f5=0 wrong MCU session")
            try: w3.close(); await w3.wait_closed()
            except Exception: pass
            self._voice_writer = None; self._voice_reader = None; return
        custom = HELLXbuild_voice_custom(self.uid, self.voice_region_id, mcu_ip=voice_ip, region_prefix=self.region_prefix)
        w3.write(custom[:4]); await w3.drain()
        w3.write(custom[4:]); await w3.drain()
        try:
            resp4 = await _read_voice_frame(r3, 3.0)
            if resp4:
                raw = resp4[4:] if resp4[:4] != b'\xfe\xff\xff\x7f' else resp4
                idx = raw.find(b'\xfe\xff\xff\x7f')
                if idx != -1:
                    ts_idx = raw.find(b'\x17\x76', idx)
                    if ts_idx != -1 and ts_idx + 6 <= len(raw):
                        self.voice_session_ts = raw[ts_idx + 2:ts_idx + 6]
        except asyncio.TimeoutError: pass
        if self._voice_ping_task: self._voice_ping_task.cancel()
        self._voice_ping_task = asyncio.create_task(self._voice_ping_loop(w3, r3))
        self._voice_ip = voice_ip; self._voice_port = voice_port

        async def _voice_tcp_reader():
            try:
                while True:
                    try: data = await _read_voice_frame(r3, 30.0)
                    except (asyncio.IncompleteReadError, ConnectionError):
                        if self._udp_task and not self._udp_task.done(): self._udp_task.cancel()
                        break
                    try:
                        p = HELLXdecode_proto(data)
                        inner = p.get('1', {})
                        pkt_type = inner.get('1', 0) if isinstance(inner, dict) else 0
                        field2 = p.get('2', 0)
                        if pkt_type == 0x0b and field2:
                            self._voice_ssrc_refresh = True
                            async def _do_reauth():
                                a = HELLXbuild_voice_auth(self.uid, self.voice_region_id, voice_port, self.region_prefix)
                                w3.write(a[:4]); await w3.drain()
                                w3.write(a[4:]); await w3.drain()
                                c = HELLXbuild_voice_custom(self.uid, self.voice_region_id, mcu_ip=voice_ip, region_prefix=self.region_prefix)
                                w3.write(c[:4]); await w3.drain()
                                w3.write(c[4:]); await w3.drain()
                            asyncio.create_task(_do_reauth())
                    except Exception: pass
            except Exception as e:
                HELLXlog("VOICE", f"TCP reader error: {e}")
        asyncio.create_task(_voice_tcp_reader())
        HELLXlog("VOICE", f"Step3: Done. Streaming to {voice_ip}:{voice_port + 2}")

    async def _voice_ping_loop(self, writer, reader):
        try:
            while writer and not writer.transport.is_closing():
                await asyncio.sleep(5)
                try:
                    ping_pkt = HELLXbuild_voice_ping(self.uid, self.voice_region_id,
                                                     self.voice_port, getattr(self, '_voice_f3', 0x0b))
                    writer.write(ping_pkt); await writer.drain()
                except Exception: break
        except asyncio.CancelledError: pass

    async def _voice_udp_loop(self, ip, port, encode_task=None, ogg_data=None, start_frame=0):
        import socket as _sock
        udp_port = port + 2
        if ogg_data is None and encode_task is not None: ogg_data = await encode_task
        if not ogg_data: return
        frames = list(_ogg_opus_frames_bytes(ogg_data))
        converted = []
        for f in frames:
            if f[0] == 0x78: continue
            if f[0] == 0x4b and len(f) > 2 and f[1] == 0x01: converted.append(bytes([0x48]) + f[2:])
            else: converted.append(f)
        frames = converted
        udp = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        magic = b'\x41\x6f'
        seq = random.randint(0, 0xFFFF)
        ts = random.randint(0, 0xFFFFFFFF)
        FRAME_SAMPLES = 0x3c0
        FRAME_DURATION = 0.020
        f3_val = getattr(self, '_voice_f3', 0x13e6)
        FIXED_2 = b'\x00\x00' + f3_val.to_bytes(2, 'big')
        mic_open = (b'\x71\x5c\x35\x07\x00\x00\x00\x00\x80\x02\x00\x00\x00\x00' +
                    f3_val.to_bytes(2, 'big'))
        udp.setblocking(False)
        try: udp.sendto(mic_open, (ip, udp_port))
        except OSError: pass
        try:
            while True:
                seq_loop = seq; ts_loop = ts; loop_start = start_frame
                self._track_current_frame = loop_start
                next_send = time.monotonic()
                for i in range(loop_start, len(frames)):
                    opus_frame = frames[i]
                    f5_val = getattr(self, '_voice_f5', 0)
                    FIXED_1 = f5_val.to_bytes(4, 'big')
                    header = struct.pack('>2sHI4s4s', magic, seq_loop & 0xFFFF,
                                         ts_loop & 0xFFFFFFFF, FIXED_1, FIXED_2)
                    try: udp.sendto(header + opus_frame, (ip, udp_port))
                    except Exception: pass
                    self._track_current_frame = i
                    seq_loop = (seq_loop + 1) & 0xFFFF
                    ts_loop = (ts_loop + FRAME_SAMPLES) & 0xFFFFFFFF
                    next_send += FRAME_DURATION
                    sleep_time = next_send - time.monotonic()
                    if sleep_time > 0:
                        try: await asyncio.sleep(sleep_time)
                        except asyncio.CancelledError:
                            self._stopped_frame = i; raise
                seq = seq_loop; ts = ts_loop; start_frame = 0
        except asyncio.CancelledError: pass
        except Exception as e:
            HELLXlog("VOICE", f"UDP: FATAL ERROR {type(e).__name__}: {e}")
        finally: udp.close()

    async def _play_yt(self, url, lyrics=False):
        import subprocess, tempfile as _tmp, glob as _glob, hashlib
        self._current_url = url
        if self._udp_task and not self._udp_task.done():
            self._udp_task.cancel(); await asyncio.sleep(0.3)
        if not self._voice_ip or not self._voice_port:
            await self._send_chat_message("[FF0000][b][i]جاري تجهيز الصوت...[/i][/b]")
            deadline = asyncio.get_running_loop().time() + 20.0
            while (not self._voice_ip or not self._voice_port) and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.25)
            if not self._voice_ip or not self._voice_port:
                await self._send_chat_message("[FF0000][b][i]فشل الاتصال الصوتي[/i][/b]"); return
        vid_match = re.search(r'[?&]v=([\w-]{11})', url)
        cache_key = vid_match.group(1) if vid_match else hashlib.md5(url.encode()).hexdigest()[:16]
        cache_file = os.path.join(_CACHE_DIR, f"{cache_key}.opus")
        volume_val = self._volume / 100.0

        def _encode():
            if os.path.exists(cache_file) and os.path.getsize(cache_file) > 1000:
                HELLXlog("VOICE", f"Cache hit: {cache_file}")
                return open(cache_file, 'rb').read()
            raw_path = _tmp.mktemp()
            ffmpeg_path = _ffmpeg_executable()
            subprocess.run([*_yt_dlp_command(), "-x", "--audio-format", "wav",
                "--audio-quality", "0", "--ffmpeg-location", ffmpeg_path,
                "-o", raw_path + ".%(ext)s", "--no-playlist",
                "--concurrent-fragments", "8", "--http-chunk-size", "10M",
                "--no-warnings", "--no-check-certificate", url],
                check=True, capture_output=True, text=True)
            matches = _glob.glob(raw_path + ".*")
            if not matches: raise Exception("yt-dlp produced no output file")
            raw_file = matches[0]
            wav_path = _tmp.mktemp(suffix='.wav')
            subprocess.run([_ffmpeg_executable(), "-loglevel", "quiet", "-y", "-threads", "0",
                "-i", raw_file, "-ar", "16000", "-ac", "1",
                "-af", f"volume={volume_val},loudnorm=I=-16:TP=-1.5:LRA=11", wav_path], check=True)
            try: os.unlink(raw_file)
            except: pass
            ogg_path = _tmp.mktemp(suffix='.opus')
            subprocess.run([_ffmpeg_executable(), "-loglevel", "error", "-y", "-threads", "0",
                "-i", wav_path, "-c:a", "libopus", "-application", "voip",
                "-b:a", "96000", "-vbr", "off",
                "-frame_duration", "20", "-ar", "16000", "-ac", "1",
                "-f", "ogg", ogg_path], check=True)
            data = open(ogg_path, 'rb').read()
            try:
                with open(cache_file, 'wb') as cf: cf.write(data)
            except: pass
            for p in (wav_path, ogg_path):
                try: os.unlink(p)
                except: pass
            return data

        loop = asyncio.get_event_loop()
        try: ogg_data = await loop.run_in_executor(None, _encode)
        except Exception as e:
            await self._send_chat_message(f"[FF0000][b][i]Download failed: {str(e)[:60]}[/i][/b]"); return
        await self._send_chat_message(
            f"[FF0000][b][i]NOW PLAYING[/i][/b]\n"
            f"[00BFFF][b][i]{self._track_title[:45]}[/i][/b]\n"
            f"[FF0000][b][i]{self._track_channel[:30]}[/i][/b]")
        self._current_ogg = ogg_data
        self._track_total_frames = len(list(_ogg_opus_frames_bytes(ogg_data)))
        self._track_current_frame = 0
        self._udp_task = asyncio.create_task(
            self._voice_udp_loop(self._voice_ip, self._voice_port, ogg_data=ogg_data))


def _pb_varint(n):
    if n < 0: n = (1 << 64) + n
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)


def _pb_tag(f, w): return _pb_varint((f << 3) | w)


def _pb_field(f, v):
    if isinstance(v, bool): v = int(v)
    if isinstance(v, int): return _pb_tag(f, 0) + _pb_varint(v)
    if isinstance(v, str):
        d = v.encode('utf-8'); return _pb_tag(f, 2) + _pb_varint(len(d)) + d
    if isinstance(v, (bytes, bytearray)):
        d = bytes(v); return _pb_tag(f, 2) + _pb_varint(len(d)) + d
    return b""


async def aes_encrypt(payload, key, iv):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(payload, AES.block_size))


def get_proto_field(d, key, default=None):
    if not d or not isinstance(d, dict): return default
    if key in d: return d[key].get('data', default)
    if str(key) in d: return d[str(key)].get('data', default)
    return default


async def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        fd = {"wire_type": result.wire_type}
        if result.wire_type in ("varint", "string", "bytes"): fd["data"] = result.data
        elif result.wire_type == "length_delimited":
            if hasattr(result.data, "results"): fd["data"] = await parse_results(result.data.results)
            elif isinstance(result.data, list): fd["data"] = await parse_results(result.data)
            else: fd["data"] = str(result.data)
        result_dict[str(result.field)] = fd
    return result_dict


async def get_playstore_version():
    loop = asyncio.get_event_loop()
    try:
        res = await loop.run_in_executor(
            None, lambda: play_scraper('com.dts.freefireth', lang='hi', country='id'))
        return res.get("version", "1.134.21")
    except Exception: return "1.134.21"


async def version_config(client_http, region="IND"):
    app_version = await get_playstore_version()
    lang = REGION_LANG.get(region, "hi")
    api_url = (f"https://version.ggwhitehawk.com/live/ver.php?version={app_version}"
               f"&lang={lang}&device=android&channel=android&appstore=googleplay"
               f"&region={region}&whitelist_version=1.3.0&whitelist_sp_version=1.0.0")
    try:
        res = await client_http.get(api_url)
        data = res.json()
        return (data.get("latest_release_version"), data.get("remote_version"), data.get("server_url"))
    except Exception: return None


async def get_access_token(client_http, uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    hdrs = {"Host": "100067.connect.garena.com",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br", "Connection": "close"}
    data = {"uid": str(uid), "password": str(password), "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"}
    for _ in range(3):
        try:
            r = await client_http.post(url, headers=hdrs, data=data)
            if r.status_code == 200:
                rd = r.json()
                return rd.get("open_id"), rd.get("access_token"), rd.get("platform", 4)
        except Exception: pass
        await asyncio.sleep(0.5)
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
        proto.screen_width = 1600; proto.screen_height = 720; proto.screen_dpi = "300"
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
        if field_29: extra += _pb_field(29, str(field_29))
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
        log.error(f"build_majorlogin_payload: {e}"); return None


async def send_majorlogin(client_http, data, release_version, server_url):
    try:
        url = f"{server_url}MajorLogin" if server_url.endswith('/') else f"{server_url}/MajorLogin"
        req_headers = DEFAULT_HEADERS.copy()
        req_headers["ReleaseVersion"] = str(release_version)
        response = await client_http.post(url, headers=req_headers, data=data)
        if response.status_code != 200 or len(response.content) < 40:
            log.warning(f"MajorLogin HTTP {response.status_code}"); return None
        res_proto = MajoRLoGinrEs_pb2.MajorLoginRes()
        try: res_proto.ParseFromString(response.content)
        except Exception: pass
        if not (res_proto.account_uid and res_proto.token):
            for offset in range(min(128, len(response.content))):
                try:
                    c = MajoRLoGinrEs_pb2.MajorLoginRes()
                    c.ParseFromString(response.content[offset:])
                    if c.account_uid and c.token: res_proto = c; break
                except Exception: pass
        parsed = Parser().parse(response.content.hex())
        dict_res = await parse_results(parsed)
        key_val = get_proto_field(dict_res, 22) or res_proto.key or AES_KEY
        iv_val = get_proto_field(dict_res, 23) or res_proto.iv or AES_IV
        if isinstance(key_val, str):
            try: key_val = bytes.fromhex(key_val)
            except Exception: pass
        if isinstance(iv_val, str):
            try: iv_val = bytes.fromhex(iv_val)
            except Exception: pass
        res_proto.key = key_val; res_proto.iv = iv_val
        if not res_proto.url: res_proto.url = server_url
        return res_proto
    except Exception as e:
        log.error(f"MajorLogin error: {e}"); return None


async def send_getlogin(client_http, data, base_url, token, release_version):
    try:
        url = f"{base_url.rstrip('/')}/GetLoginData"
        req_headers = DEFAULT_HEADERS.copy()
        req_headers["ReleaseVersion"] = str(release_version)
        req_headers['Authorization'] = f"Bearer {token}"
        response = await client_http.post(url, headers=req_headers, data=data)
        if response.status_code != 200: return None
        res_proto = PorTs_pb2.GetLoginData()
        try: res_proto.ParseFromString(response.content)
        except Exception: pass
        parsed = Parser().parse(response.content.hex())
        dict_res = await parse_results(parsed)
        return res_proto, dict_res
    except Exception as e:
        log.error(f"GetLoginData error: {e}"); return None


async def do_login(uid, password, region_pref="ME"):
    async with httpx.AsyncClient(verify=False, timeout=15.0) as client_http:
        vc = await version_config(client_http, region_pref)
        if not vc:
            log.error("version_config failed"); return None
        release_version, client_version, server_url = vc
        tg = await get_access_token(client_http, uid, password)
        if not tg:
            log.error(f"access_token failed for {uid}"); return None
        open_id, access_token, platform = tg
        payload = await build_majorlogin_payload(open_id, access_token, platform, client_version, region_pref)
        if not payload:
            log.error("payload build failed"); return None
        major_res = await send_majorlogin(client_http, payload, release_version, server_url)
        if not major_res or not major_res.account_uid:
            log.error(f"MajorLogin rejected for {uid}"); return None
        gl = await send_getlogin(client_http, payload, major_res.url, major_res.token, release_version)
        if not gl:
            log.error(f"GetLoginData failed for {uid}"); return None
        res_proto, dict_res = gl
        online_addr = res_proto.Online_IP_Port or get_proto_field(dict_res, 14, "0.0.0.0:0")
        online_ip, online_port = online_addr.split(":") if ':' in online_addr else ("0.0.0.0", "0")
        chat_addr = res_proto.AccountIP_Port or get_proto_field(dict_res, 32, online_addr)
        chat_ip, chat_port = chat_addr.split(":") if ':' in chat_addr else (online_ip, online_port)
        return {
            "bot_uid": str(major_res.account_uid), "token": major_res.token,
            "region": major_res.region or region_pref,
            "key": major_res.key or AES_KEY, "iv": major_res.iv or AES_IV,
            "timestamp": major_res.timestamp or int(time.time()),
            "online_ip": online_ip, "online_port": online_port,
            "chat_ip": chat_ip, "chat_port": chat_port,
            "account_name": res_proto.AccountName or "Unknown",
            "clan_id": res_proto.Clan_ID or 0,
            "clan_data": res_proto.Clan_Compiled_Data or "",
            "server_url": major_res.url,
            "login_data_raw": None,
        }


WELCOME_TEXT = "[00BFFF][b][i]WELCOME TO JAGWAR x STRAVEX[/i][/b]"
HELP_TEXT = (
    "[FF0000][b][i]JAGWAR x STRAVEX COMMANDS[/i][/b]\n\n"
    "[00BFFF][b][i]شغل أغنية[/i][/b]\n"
    "[FF0000][b][i]/voice <name>[/i][/b]\n\n"
    "[00BFFF][b][i]إيقاف الأغنية[/i][/b]\n"
    "[FF0000][b][i]/stop[/i][/b]\n\n"
    "[00BFFF][b][i]FF BOT OB55[/i][/b]"
)


def _fmt(sec):
    m, s = divmod(int(max(sec or 0, 0)), 60)
    return f"{m}:{s:02d}"


def _ytdl_search(query, n=1):
    import yt_dlp
    opts = {"quiet": True, "skip_download": True, "extract_flat": True,
            "noplaylist": True, "no_warnings": True, "nocheckcertificate": True}
    with yt_dlp.YoutubeDL(opts) as ydl:
        if query.startswith(("http://", "https://")):
            info = ydl.extract_info(query, download=False)
            return [{"title": info.get("title") or query, "url": info.get("webpage_url") or query,
                     "channel": info.get("uploader") or info.get("channel") or "",
                     "duration": int(info.get("duration") or 0)}]
        info = ydl.extract_info(f"ytsearch{n}:{query}", download=False)
    out = []
    for e in info.get("entries") or []:
        out.append({"title": e.get("title") or "?",
                    "url": e.get("url") or f"https://www.youtube.com/watch?v={e.get('id')}",
                    "channel": e.get("uploader") or e.get("channel") or "",
                    "duration": int(e.get("duration") or 0)})
    return out


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
        self._chat_buf = bytearray(); self._online_buf = bytearray()
        self._tasks = []; self.closed = False
        self.persistent = False; self._last_invite = None
        self.owner_uid = None; self.voice_region_id = None
        self.chat_region_id = None; self._joined = asyncio.Event()
        self.voice = None

    def _spawn(self, coro):
        t = asyncio.create_task(coro); self._tasks.append(t); return t

    async def connect(self):
        r = self.login
        self.chat_r, self.chat_w = await asyncio.wait_for(
            asyncio.open_connection(r["chat_ip"], int(r["chat_port"])), 10)
        self.chat_w.write(bytes.fromhex(
            HELLXbuild_auth_startup(self.uid, self.token, self.ts, self.key, self.iv)))
        await self.chat_w.drain()
        self._spawn(self._chat_read_loop())
        self._spawn(self._keepalive(self.chat_w))
        await asyncio.sleep(1)
        auth, _ = build_ob55_online_auth(self.uid, self.token, self.ts, self.key, self.iv)
        self.online_r, self.online_w = await asyncio.wait_for(
            asyncio.open_connection(r["online_ip"], int(r["online_port"])), 10)
        self.online_w.write(auth); await self.online_w.drain()
        self._spawn(self._online_read_loop())
        self._spawn(self._keepalive(self.online_w))
        self.voice = VoicePlayer(str(self.uid), region_prefix=self.region.upper(),
                                 ext_region=self.region.lower()[:2], send_chat=self.say)
        self.voice.configure(r.get("login_data_raw"), self.region)

    async def _keepalive(self, writer):
        try:
            while not self.closed and not writer.transport.is_closing():
                await asyncio.sleep(5)
                try:
                    writer.write(bytes.fromhex("0201")); await writer.drain()
                except Exception: break
        except asyncio.CancelledError: pass

    async def join(self, team_code, timeout=12):
        self._joined.clear()
        self.online_w.write(await JoinSq_original(str(team_code), self.key, self.iv))
        await self.online_w.drain()
        try:
            await asyncio.wait_for(self._joined.wait(), timeout); return True
        except asyncio.TimeoutError: return False

    async def _on_joined(self, f5):
        self.voice_region_id = int(f5.get("17"))
        self.chat_region_id = int(self.voice_region_id / 256 + 0.5) * 256
        try: self.owner_uid = int(f5.get("1", self.uid))
        except Exception: self.owner_uid = self.uid
        self._joined.set()
        try:
            self.chat_w.write(HELLXbuild_chat_auth(self.owner_uid, str(self.chat_region_id), self.key, self.iv))
            await self.chat_w.drain()
        except Exception as e: log.warning(f"chat auth failed: {e}")
        if self.voice:
            self.voice.stop()
            self.voice.voice_region_id = None
            self.voice.start(self.voice_region_id)
        await asyncio.sleep(1.5)
        await self.say(WELCOME_TEXT)
        await asyncio.sleep(1)
        await self.say(HELP_TEXT)

    async def leave(self):
        try:
            self.online_w.write(await ExiT(None, self.key, self.iv))
            await self.online_w.drain()
        except Exception: pass
        self._reset_team()

    def _reset_team(self):
        if self.voice: self.voice.stop()
        self.voice_region_id = self.chat_region_id = self.owner_uid = None
        self._last_invite = None
        self._joined.clear()

    @property
    def in_team(self): return bool(self.voice_region_id)

    async def _online_read_loop(self):
        try:
            while True:
                data = await self.online_r.read(16384)
                if not data: break
                self._online_buf.extend(data)
                await self._drain_frames(self._online_buf, self._on_online_packet)
        except asyncio.CancelledError: return
        except Exception as e: log.warning(f"online loop: {e}")
        await self.close()

    async def _chat_read_loop(self):
        try:
            while True:
                data = await self.chat_r.read(16384)
                if not data: break
                self._chat_buf.extend(data)
                await self._drain_frames(self._chat_buf, self._on_chat_packet)
        except asyncio.CancelledError: return
        except Exception as e: log.warning(f"chat loop: {e}")

    @staticmethod
    async def _drain_frames(buf, handler):
        pos = 0
        while len(buf) - pos >= 5:
            length = struct.unpack(">I", buf[pos + 1:pos + 5])[0]
            if 0 < length < 200000:
                if pos + 5 + length > len(buf): break
                payload = bytes(buf[pos + 5:pos + 5 + length])
                try:
                    pd = HELLXdecode_proto(payload)
                    if pd: await handler(pd)
                except Exception as e: log.warning(f"packet error: {e}")
                pos += 5 + length
            else: pos += 1
        if pos: del buf[:pos]

    async def _on_online_packet(self, pd):
        f5 = pd.get("5")
        if not isinstance(f5, dict): return
        code = f5.get("8")
        if isinstance(code, str) and "_" in code and code != self._last_invite \
                and self.persistent and not self.in_team:
            self._last_invite = code
            try:
                owner = int(f5.get("1", self.uid))
                self.online_w.write(await MahirAccepted(owner, code, self.key, self.iv, self.region))
                await self.online_w.drain()
            except Exception as e: log.warning(f"accept invite failed: {e}")
        if not self.voice_region_id and f5.get("17"):
            await self._on_joined(f5)

    async def _on_chat_packet(self, pd):
        f5 = pd.get("5")
        if not isinstance(f5, dict): return
        sender = str(f5.get("1", ""))
        message = f5.get("4", "")
        if not isinstance(message, str) or not message.strip(): return
        if sender == str(self.uid) or not self.in_team: return
        asyncio.create_task(self.handle_command(message.strip(), sender))

    async def say(self, message):
        if not self.chat_w or self.chat_w.transport.is_closing(): return
        try:
            owner = self.owner_uid or self.uid
            pkt = await HELLXbuild_chat_message(self.uid, owner, message,
                                                int(time.time()), self.key, self.iv, name=self.name)
            self.chat_w.write(pkt); await self.chat_w.drain()
        except Exception as e: log.warning(f"send failed: {e}")

    async def handle_command(self, message, sender_uid=None):
        msg = message.strip()
        if msg.startswith("/") and not msg.startswith("//"): msg = "@" + msg[1:]
        if not msg.startswith("@"): return
        parts = msg.split(); cmd = parts[0].lower(); args = parts[1:]
        try:
            if cmd in ("@voice", "@play"):
                if not args: return
                await self._play_query(" ".join(args))
            elif cmd == "@stop": await self._stop()
            elif cmd == "@help": await self.say(HELP_TEXT)
            elif cmd == "@leave":
                await self.say("[FF0000][b][i]إلى اللقاء[/i][/b]")
                await asyncio.sleep(1)
                if self.persistent: await self.leave()
                else: await self.close()
        except Exception as e:
            log.warning(f"command error: {e}")

    async def _play_query(self, query):
        loop = asyncio.get_running_loop()
        await self.say(f"[00BFFF][b][i]جاري البحث عن: {query[:40]}[/i][/b]")
        results = await loop.run_in_executor(None, _ytdl_search, query, 1)
        if not results:
            await self.say("[FF0000][b][i]ما لقيت الأغنية[/i][/b]"); return
        await self._play_item(results[0])

    async def _play_item(self, item):
        v = self.voice
        v._track_title = item["title"]
        v._track_channel = item.get("channel", "")
        await self.say(
            f"[FF0000][b][i]{item['title'][:50]}[/i][/b]\n"
            f"[00BFFF][b][i]{_fmt(item.get('duration'))} • {item.get('channel', '')[:30]}[/i][/b]")
        asyncio.create_task(self._play_voice(item["url"]))

    async def _play_voice(self, url):
        try: await self.voice.play(url)
        except asyncio.CancelledError: pass
        except Exception as e:
            log.warning(f"voice play failed: {e}")
            await self.say("[FF0000][b][i]تعذر تشغيل الصوت[/i][/b]")

    async def _stop(self):
        v = self.voice
        playing = v._udp_task and not v._udp_task.done()
        if playing:
            v._udp_task.cancel()
            v._stopped_frame = v._track_current_frame
            await self.say(
                f"[FF0000][b][i]تم إيقاف التشغيل[/i][/b]\n"
                f"[00BFFF][b][i]{v._track_title}[/i][/b]")
        else:
            await self.say("[FF0000][b][i]ما في شي شغال[/i][/b]")

    async def close(self):
        if self.closed: return
        self.closed = True
        self._reset_team()
        for w in (self.online_w, self.chat_w):
            if w:
                try:
                    if w is self.online_w and not w.transport.is_closing():
                        w.write(await ExiT(None, self.key, self.iv)); await w.drain()
                except Exception: pass
                try: w.close()
                except Exception: pass
        me = asyncio.current_task()
        for t in self._tasks:
            if t is not me and not t.done(): t.cancel()
        if self.on_close:
            try: self.on_close(self)
            except Exception: pass


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


async_loop = AsyncLoop()


class AccountPool:
    def __init__(self):
        self.accounts = []; self.lock = asyncio.Lock()
        self.current_index = 0; self.loading = False; self.loaded = False

    async def load_and_connect(self):
        self.loading = True
        if not os.path.exists("accs.txt"):
            log.warning("accs.txt not found")
            self.loading = False; self.loaded = True; return
        with open("accs.txt", "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if ":" in l]
        print(f"LOADED {len(lines)} ACCOUNTS FROM accs.txt")
        for line in lines:
            uid, password = line.split(":", 1)
            uid, password = uid.strip(), password.strip()
            try:
                login = await asyncio.to_thread(self._sync_login, uid, password)
                if not login: continue
                bot = SquadBot(login)
                await bot.connect()
                bot.persistent = True
                async with self.lock: self.accounts.append(bot)
                print(f"ACCOUNT {uid} CONNECTED SUCCESFULLY .")
                await asyncio.sleep(0.3)
            except Exception as e:
                log.error(f"account {uid} error: {e}")
        self.loading = False; self.loaded = True

    def _sync_login(self, uid, password):
        try:
            loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
            result = loop.run_until_complete(do_login(uid, password, "ME"))
            loop.close(); return result
        except Exception as e:
            log.error(f"Login thread error: {e}"); return None

    async def get_next_bot(self):
        async with self.lock:
            if not self.accounts: return None
            bot = self.accounts[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.accounts)
            return bot

    async def wait_for_account(self, timeout=20):
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            bot = await self.get_next_bot()
            if bot: return bot
            if self.loaded and not self.accounts: return None
            await asyncio.sleep(1)
        return await self.get_next_bot()


account_pool = AccountPool()


async def run_join(team_code):
    team_code = team_code.strip()
    if not team_code.isdigit(): return False
    bot = await account_pool.wait_for_account()
    if not bot: return False
    if getattr(bot, "in_team", False): return True
    joined = await bot.join(team_code)
    if not joined: return False
    await asyncio.sleep(2)
    print(f"SUCCESS JOINED TO {team_code}")
    return True


app = Flask(__name__)


@app.route("/join", methods=["GET", "POST"])
def join():
    team_code = (request.args.get("team_code", "") if request.method == "GET"
                 else (request.get_json(silent=True) or {}).get("team_code", ""))
    if not team_code:
        return jsonify({"success": False, "message": "Failed",
                        "team_code": team_code, "DEV": DEV_NAME}), 400
    try:
        success = async_loop.run(run_join(team_code))
    except Exception as e:
        log.exception("join error")
        return jsonify({"success": False, "message": "Failed",
                        "team_code": team_code, "DEV": DEV_NAME}), 500
    if success:
        return jsonify({"success": True, "message": "Done",
                        "team_code": team_code, "DEV": DEV_NAME}), 200
    return jsonify({"success": False, "message": "Failed",
                    "team_code": team_code, "DEV": DEV_NAME}), 502


if __name__ == "__main__":
    async_loop.run(account_pool.load_and_connect())
    app.run(host="0.0.0.0", port=8000, threaded=True)