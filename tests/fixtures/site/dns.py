#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns.py — recon.sh の DNS まわりを検査するための受け口

    python3 dns.py [ポート]        （既定 5353。UDP）

どのドメインを聞かれても、決まった応答を返す。外へは一切出ない。
わざと穴のある構成を模してある。

  - SPF は無い（apex の TXT に v=spf1 が無い）
  - DMARC は p=none（監視だけで隔離・拒否をしない）
  - CAA は無い
  - DS は無い（DNSSEC 未署名）
  - 配信サービス用のサブドメイン send.<domain> に SPF がある
  - DKIM セレクタ resend._domainkey が存在する

ただし strict.test 配下だけは、**正しく作られた親ドメイン**を模す。設定は親（strict.test）にだけあり、
サブドメイン（app.strict.test）には何も無い。recon.sh がサブドメインを渡されたときに
親へ遡って見つけられるか、p=reject; sp=none を「p=none」と取り違えないかを見る。

  - _dmarc.strict.test に v=DMARC1; p=reject; sp=none
  - strict.test に CAA と DS（DNSSEC 署名済み）
  - SOA は strict.test が持つ（サブドメインを問い合わせると、権威部に strict.test の SOA が返る）。
    recon.sh はこれでゾーンの頂点を求め、DS をそこだけで引く

標準ライブラリだけで、RFC 1035 の応答を組み立てる。TXT / MX / NS / A / CAA / DS / AAAA に答える。
"""
import socket, struct, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5353

QTYPE = {1: "A", 2: "NS", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 43: "DS", 257: "CAA"}

def parse_name(data, off):
    labels = []
    while True:
        n = data[off]
        if n == 0:
            off += 1; break
        if n & 0xC0 == 0xC0:               # 圧縮ポインタ（質問部には普通出ないが念のため）
            ptr = struct.unpack("!H", data[off:off+2])[0] & 0x3FFF
            sub, _ = parse_name(data, ptr)
            labels.append(sub); off += 2; break
        labels.append(data[off+1:off+1+n].decode("ascii", "replace")); off += 1 + n
    return ".".join(labels), off

def enc_name(name):
    out = b""
    for lab in name.rstrip(".").split("."):
        if lab:
            b = lab.encode("ascii"); out += bytes([len(b)]) + b
    return out + b"\x00"

def rr(name, rtype, rdata, ttl=60):
    return enc_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata

def txt(s):
    b = s.encode("ascii"); return bytes([len(b)]) + b

def answers(qname, qtype):
    q = qname.lower().rstrip(".")
    base = q
    for pre in ("_dmarc.", "send.", "resend._domainkey.", "mail."):
        if q.startswith(pre): base = q[len(pre):]
    out = []
    if qtype == 6:  # SOA は answers ではなく soa_of で扱う
        return out
    # タグの書き方の揺れ（大文字・空白）と、DMARC のレコードが 2 本ある構成
    if q == "_dmarc.caps.test" and qtype == 16:
        return [rr(qname, 16, txt("v=DMARC1; P = Reject; SP=None"))]
    if q == "_dmarc.dup.test" and qtype == 16:
        return [rr(qname, 16, txt("v=DMARC1; p=reject")), rr(qname, 16, txt("v=DMARC1; p=none"))]
    if q.endswith("caps.test") or q.endswith("dup.test"):
        return [rr(qname, 1, bytes([127, 0, 0, 1]))] if qtype == 1 else []
    if q == "strict.test" or q.endswith(".strict.test"):
        if qtype == 16 and q == "_dmarc.strict.test":
            out.append(rr(qname, 16, txt("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.invalid")))
        elif qtype == 257 and q == "strict.test":
            tag, val = b"issue", b"ca.example.invalid"
            out.append(rr(qname, 257, bytes([0, len(tag)]) + tag + val))
        elif qtype == 43 and q == "strict.test":
            out.append(rr(qname, 43, struct.pack("!HBB", 12345, 13, 2) + bytes(32)))
        elif qtype == 1:
            out.append(rr(qname, 1, bytes([127, 0, 0, 1])))
        return out
    if qtype == 16:  # TXT
        if q.startswith("_dmarc."):
            out.append(rr(qname, 16, txt("v=DMARC1; p=none; rua=mailto:dmarc@example.invalid")))
        elif q.startswith("send."):
            out.append(rr(qname, 16, txt("v=spf1 include:_spf.example.invalid ~all")))
        elif q.startswith("resend._domainkey."):
            out.append(rr(qname, 16, txt("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdummy")))
        else:
            # apex には SPF を置かない（穴）。無関係な TXT だけ返す
            out.append(rr(qname, 16, txt("google-site-verification=dummy")))
    elif qtype == 15:  # MX
        if q.startswith("send."):
            out.append(rr(qname, 15, struct.pack("!H", 10) + enc_name("feedback-smtp.example.invalid")))
        else:
            out.append(rr(qname, 15, struct.pack("!H", 10) + enc_name("mx." + base)))
    elif qtype == 2:   # NS
        out.append(rr(qname, 2, enc_name("ns1.example.invalid")))
        out.append(rr(qname, 2, enc_name("ns2.example.invalid")))
    elif qtype == 1:   # A
        out.append(rr(qname, 1, bytes([127, 0, 0, 1])))
    elif qtype == 28:  # AAAA
        out.append(rr(qname, 28, bytes(15) + b"\x01"))
    # CAA(257) と DS(43) は返さない = 未設定
    return out

def soa_of(qname):
    """問い合わせた名前が属するゾーンの頂点と、その SOA レコード"""
    q = qname.lower().rstrip(".")
    apex = "strict.test" if (q == "strict.test" or q.endswith(".strict.test")) else ".".join(q.split(".")[-2:])
    rdata = enc_name("ns1.example.invalid") + enc_name("hostmaster.example.invalid") + struct.pack("!IIIII", 1, 3600, 600, 86400, 60)
    return apex, rr(apex, 6, rdata)

def build(req):
    tid = req[:2]
    qd = struct.unpack("!H", req[4:6])[0]
    off = 12
    qname, off2 = parse_name(req, off)
    qtype, qclass = struct.unpack("!HH", req[off2:off2+4])
    question = req[12:off2+4]
    ans = answers(qname, qtype)
    auth = []
    if qtype == 6:
        apex, soa = soa_of(qname)
        # 頂点そのものなら回答部に、サブドメインなら権威部に SOA を返す（実際の権威サーバーと同じ）
        if qname.lower().rstrip(".") == apex: ans = [soa]
        else: auth = [soa]
    flags = 0x8180  # 応答・再帰可・エラーなし
    hdr = tid + struct.pack("!HHHHH", flags, 1, len(ans), len(auth), 0)
    return hdr + question + b"".join(ans) + b"".join(auth), qname, QTYPE.get(qtype, str(qtype))

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", PORT))
    print(f"DNS の受け口を起動した: 127.0.0.1:{PORT}（UDP）", flush=True)
    while True:
        data, addr = s.recvfrom(1024)
        try:
            resp, qn, qt = build(data)
            s.sendto(resp, addr)
        except Exception as e:  # 壊れた問い合わせで落ちないように
            print("skip:", e, file=sys.stderr, flush=True)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: pass
