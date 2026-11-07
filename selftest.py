# -*- coding: utf-8 -*-
"""自检（不联网）：python selftest.py
覆盖分享链接解析、去重指纹、外部源多协议收录与分协议限量、两种订阅格式。
"""
import base64
import json
import pathlib
import tempfile
import time

import yaml

import server


def vm(obj):
    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


# vmess 的 base64 体里含 "/"，不能交给 urlparse（会把 netloc 截断）
v = vm(dict(add="1.2.3.4", port="443", id="u", aid="0", net="ws", path="/p",
            host="h.com", tls="tls", sni="s.com", ps="名"))
assert server._vmess_json(v)["ps"] == "名"
assert server._parse_link(v) == ("vmess", "1.2.3.4", 443)
assert server.link_name(v) == "名"
assert server._parse_link("vmess://!!!") is None  # 坏链接不能抛异常

p = server._clash_proxy("vless://uuid@1.2.3.4:443?security=reality&sni=s.com&pbk=k&sid=ab&type=ws&path=%2Fq#名", "n")
assert p["type"] == "vless" and p["reality-opts"] == {"public-key": "k", "short-id": "ab"}
assert server._clash_proxy("naive+https://u:p@h:443#x", "n") is None  # mihomo 不支持
assert server._clash_proxy(vm(dict(add="1.2.3.4", port="80", net="http", path="/p")), "n")["network"] == "http"
assert server._clash_proxy(vm(dict(add="1.2.3.4", port="443", tls=True, net="tcp", ps="t")), "n")["tls"] is True

# 同 IP 换 uuid 算换节点
a = server._mk_node("vless", "1.2.3.4", 443, "id-a", "", None, [], "")
b = server._mk_node("vless", "1.2.3.4", 443, "id-b", "", None, [], "")
assert server.nodes_fingerprint([a]) != server.nodes_fingerprint([b])
# Same endpoint is not enough: auth/SNI/transport/path remain part of identity; display names do not.
v2 = vm(dict(add="1.2.3.4", port="443", id="u", aid="0", net="ws", path="/p",
             host="h.com", tls="tls", sni="s.com", ps="另一个名字"))
v3 = vm(dict(add="1.2.3.4", port="443", id="different", aid="0", net="ws", path="/p",
             host="h.com", tls="tls", sni="s.com", ps="名字"))
assert server.link_fingerprint(v) == server.link_fingerprint(v2)
assert server.link_fingerprint(v) != server.link_fingerprint(v3)
u1 = "vless://uuid@EXAMPLE.com:443?type=ws&path=%2Fws&sni=one.example#one"
u2 = "vless://uuid@EXAMPLE.com:443?sni=one.example&path=%2Fws&type=ws#renamed"
u3 = "vless://other@EXAMPLE.com:443?type=ws&path=%2Fws&sni=one.example#one"
assert server.link_fingerprint(u1) == server.link_fingerprint(u2)
assert server.link_fingerprint(u1) != server.link_fingerprint(u3)
node_a = dict(protocol="vless", links=[dict(url=u1, name="old")])
node_b = dict(protocol="vless", links=[dict(url=u2, name="renamed")])
node_c = dict(protocol="vless", links=[dict(url="vless://uuid@EXAMPLE.com:443?type=grpc&serviceName=svc&sni=one.example#one", name="other transport")])
assert server.node_fingerprint(node_a) == server.node_fingerprint(node_b)
assert server.node_fingerprint(node_a) != server.node_fingerprint(node_c)
assert server.SSL_CTX.check_hostname and server.SSL_CTX.verify_mode == server.ssl.CERT_REQUIRED

# 测活判定逻辑（不真连网）
v_tcp = vm(dict(add="1.2.3.4", port="443", id="u", net="tcp", tls="tls", sni="s.com", ps="t"))
v_ws = vm(dict(add="1.2.3.4", port="80", id="u", net="ws", path="/p", host="h.com", ps="w"))
trojan = "trojan://pw@1.2.3.4:443?sni=s.com#tr"
assert server._link_tls(v_tcp) == (True, "s.com")
assert server._link_tls(trojan) == (True, "s.com")
assert server._link_tls("ss://YWVzLTI1Ni1nY206cHc=@1.2.3.4:8388#s") == (False, "")
assert server._link_ws(v_ws) == ("h.com", "/p")
assert server._link_ws("vless://u@1.2.3.4:443?type=tcp#x") is None
assert server._probe_link("vmess://!!!") is None  # 解析不了直接判死，不抛异常

# trojan 走 ws 的两种写法（标准 / ermaozi 私有）都要能识别并转成 mihomo 的 ws 配置
tj_ws_std = "trojan://pw@1.2.3.4:443?sni=s.com&type=ws&host=h.com&path=%2Fp#a"
tj_ws_erm = "trojan://pw@1.2.3.4:443?allowInsecure=1&sni=s.com&ws=1&wspath=%2F#b"
assert server._link_ws(tj_ws_std) == ("h.com", "/p")
assert server._link_ws(tj_ws_erm) == ("", "/")
p1 = server._clash_proxy(tj_ws_std, "a")
p2 = server._clash_proxy(tj_ws_erm, "b")
assert p1["network"] == "ws" and p1["ws-opts"] == {"path": "/p", "headers": {"Host": "h.com"}}
assert p2["network"] == "ws" and p2["ws-opts"] == {"path": "/"} and p2["skip-cert-verify"] is True
p3 = server._clash_proxy("trojan://pw@1.2.3.4:443?sni=s.com#c", "c")
assert "network" not in p3  # 纯 trojan 不该多出 ws 字段

# 外部源多协议收录（缓存目录换成临时目录，不碰真实数据）
server.CACHE_DIR = pathlib.Path(tempfile.mkdtemp())
server.EXT_SOURCES = {"demo": dict(label="demo")}
h1 = "hysteria://auth@5.6.7.8:443?sni=s.com#h1"
h2 = "hysteria2://auth@5.6.7.8:444?sni=s.com#h2"
h2b = "hysteria2://auth@9.9.9.9:443?sni=s.com#h2b"
tj = "trojan://pw@7.7.7.7:443?sni=s.com#tr"
ss = "ss://YWVzLTI1Ni1nY206cHc=@8.8.8.8:8388#s"
# 旧版缓存可能混进不收的协议（tuic），ext_alive 必须挡掉
tuic = "tuic://uuid:pw@6.6.6.6:443#bad"
fresh_time = time.time() - 10
(server.CACHE_DIR / "ext_demo.json").write_text(
    json.dumps(dict(fetched=server.datetime.fromtimestamp(fresh_time).strftime("%Y-%m-%d %H:%M"),
                    fetched_at=fresh_time, total=6, nodes=[dict(url=v, name="m", ms=None),
                                                 dict(url=h1, name="h1", ms=None),
                                                 dict(url=h2, name="h2", ms=None),
                                                 dict(url=h2b, name="h2b", ms=None),
                                                 dict(url=tj, name="tr", ms=50),
                                                 dict(url=ss, name="s", ms=None),
                                                 dict(url=tuic, name="bad", ms=None)])))
urls = [u for u, _, _ in server.ext_alive()]
assert tuic not in urls and h2b in urls and tj in urls  # tuic 不收，其余全留
assert urls.index(v) < urls.index(tj) < urls.index(h1) < urls.index(h2)  # TCP 系平权按缓存顺序，延迟不参与排序

# 分协议限量：TCP 系按 EXT_KEEP_TCP，hy1 按 EXT_KEEP_HY1，hy2 按 EXT_KEEP_HY2
server.EXT_KEEP_TCP, server.EXT_KEEP_HY1, server.EXT_KEEP_HY2 = 1, 0, 1
urls = [u for u, _, _ in server.ext_alive()]
assert set(urls) == {v, h2}  # tcp 桶平权截到 1 个（按缓存顺序第一个是 vmess）、hy1 清零、hy2 截到 1 个
server.EXT_KEEP_TCP, server.EXT_KEEP_HY1, server.EXT_KEEP_HY2 = 40, 20, 60

# 两种订阅格式（外部源 6 条，其中 hy1 只进 Clash 不进 v2rayN）
assert base64.b64decode(server.build_sub()).decode().count("://") == 5
cfg = yaml.safe_load(server.build_sub_clash())
assert [g["type"] for g in cfg["proxy-groups"]] == ["select", "url-test"]
assert len(cfg["proxies"]) == 6

# Cross-source exact duplicates use the newest successful cache while preserving the source-order policy.
server.EXT_SOURCES["demo_new"] = dict(label="demo_new")
new_time = time.time() - 2
(server.CACHE_DIR / "ext_demo_new.json").write_text(json.dumps(dict(
    fetched=server.datetime.fromtimestamp(new_time).strftime("%Y-%m-%d %H:%M"), fetched_at=new_time,
    nodes=[dict(url="trojan://pw@7.7.7.7:443?sni=s.com#fresh", name="fresh", ms=20)])))
old_url = "ss://YWVzLTI1Ni1nY206cHc=@11.11.11.11:8388#stale"
(server.CACHE_DIR / "ext_stale.json").write_text(json.dumps(dict(
    fetched="old", fetched_at=time.time() - server.EXT_CACHE_MAX_AGE_SECONDS - 1,
    nodes=[dict(url=old_url, name="stale", ms=None)])))
urls_and_names = server.ext_alive()
assert any(u.endswith("#fresh") and name == "fresh" for u, name, _ in urls_and_names)
assert not any(u == old_url for u, _, _ in urls_and_names)
# Same endpoint with a different password is a distinct node and must survive cross-source dedup.
server.EXT_SOURCES["demo_auth"] = dict(label="demo_auth")
auth_url = "trojan://different-password@7.7.7.7:443?sni=s.com#different-auth"
(server.CACHE_DIR / "ext_demo_auth.json").write_text(json.dumps(dict(
    fetched=server.datetime.fromtimestamp(new_time).strftime("%Y-%m-%d %H:%M"), fetched_at=new_time,
    nodes=[dict(url=auth_url, name="different-auth", ms=25)])))
urls_and_names = server.ext_alive()
assert any(u.endswith("#fresh") for u, _, _ in urls_and_names) and any(u == auth_url for u, _, _ in urls_and_names)

# Invalid/empty 200 responses and failed atomic replacement must never destroy last-good cache.
cache_path = server.ext_cache_file("demo")
last_good = cache_path.read_bytes()
class FakeResponse:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.body
old_open_url, old_probe, old_sleep = server.open_url, server._probe_link, server.time.sleep
server.time.sleep = lambda *_: None
server.EXT_SOURCES["demo"] = dict(label="demo", url="https://feed.example/sub", mirror="https://mirror.example/sub")
try:
    for body in (b"", b"not a subscription", b"https://unsupported.example/text"):
        server.open_url = lambda *args, _body=body, **kwargs: FakeResponse(_body)
        try:
            server.refresh_ext("demo")
            raise AssertionError("invalid feed unexpectedly replaced cache")
        except RuntimeError:
            pass
        assert cache_path.read_bytes() == last_good
    valid_feed = b"hysteria2://auth@example.com:443?sni=example.com#ok"
    def fallback_open(url, *args, **kwargs):
        return FakeResponse(b"<html>upstream error</html>" if "feed.example" in url else valid_feed)
    server.open_url = fallback_open
    data = server.refresh_ext("demo")
    assert data["source"] == "jsDelivr" and data["keep"] == 1 and data["fetched_at"] > 0
    assert json.loads(cache_path.read_text())["nodes"][0]["url"].startswith("hysteria2://")
    written = cache_path.read_bytes()
    old_replace = server.os.replace
    try:
        server.os.replace = lambda *args: (_ for _ in ()).throw(OSError("simulated replace failure"))
        try:
            server._write_json_atomic(cache_path, {"nodes": []})
            raise AssertionError("atomic replace failure was not raised")
        except OSError:
            pass
        assert cache_path.read_bytes() == written
    finally:
        server.os.replace = old_replace
finally:
    server.open_url, server._probe_link, server.time.sleep = old_open_url, old_probe, old_sleep

print("selftest OK")
