"""接收缓冲区演练端到端测试：真实 UDP 套接字 + TestClient。"""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    # 每个用例一套全新 lifespan：回显端状态、epoch 都重置
    with TestClient(app) as c:
        yield c


def set_config(client, **kw):
    r = client.put("/echo/config", json=kw)
    assert r.status_code == 200, r.text
    return r.json()["epoch"]


def run_drill(client, **kw):
    kw.setdefault("message_size", 28)
    kw.setdefault("packet_count", 50)
    kw.setdefault("rcvbuf_requests", [65536, 262144])
    r = client.post("/rcvbuf/drill", json=kw)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- 基础对账


class TestDrillReconciliation:
    def test_zero_overflow_recommends_smaller_buffer(self, client):
        res = run_drill(client)
        assert res["config_epoch"] == 0
        assert res["config"] == {"mode": "normal", "drop_threshold": None}

        tiers = {t["tier"]: t for t in res["tiers"]}
        assert set(tiers) == {"a", "b"}
        for t in tiers.values():
            # 整批发出、全部实收、零溢出、对账无缺口
            assert t["sent"] == 50 and t["send_failures"] == 0
            assert t["received"] == 50 and t["kernel_overflow"] == 0
            assert t["unattributed"] == 0 and t["reconciled"] is True
            assert t["passed"] == 50 and t["rule_dropped"] == 0
            assert t["actual_rcvbuf"] >= t["requested_rcvbuf"] > 0
            # 逐包记录：序号、配置版本、判定齐全
            assert [p["seq"] for p in t["packets"]] == list(range(1, 51))
            assert all(p["config_epoch"] == 0 for p in t["packets"])
            assert all(p["verdict"] == "pass" for p in t["packets"])

        rec = res["recommendation"]
        assert rec["status"] == "recommended"
        # 推荐零溢出中实际缓冲区最小的一档
        smaller = min(tiers.values(), key=lambda t: t["actual_rcvbuf"])
        assert rec["tier"] == smaller["tier"]
        assert rec["actual_rcvbuf"] == smaller["actual_rcvbuf"]
        assert rec["requested_rcvbuf"] == smaller["requested_rcvbuf"]

    def test_both_overflow_reports_insufficient(self, client):
        # 4096 × 1400 字节灌进极小的缓冲区，两档必然溢出
        res = run_drill(
            client, message_size=1400, packet_count=4096, rcvbuf_requests=[256, 512]
        )
        for t in res["tiers"]:
            assert t["sent"] == 4096 and t["send_failures"] == 0
            assert t["kernel_overflow"] is not None and t["kernel_overflow"] > 0
            assert t["received"] < 4096
            # 三方对账：发送成功 = 实收 + 内核溢出，未归因为 0
            assert t["received"] + t["kernel_overflow"] == t["sent"]
            assert t["unattributed"] == 0 and t["reconciled"] is True
            assert len(t["packets"]) == t["received"]

        rec = res["recommendation"]
        assert rec["status"] == "insufficient"
        assert rec["tier"] is None
        assert "均不足" in rec["reason"]

    def test_one_overflowing_tier_recommends_the_other(self, client):
        # a 档缓冲区装不下整批，b 档足够 → 推荐 b
        res = run_drill(
            client,
            message_size=1400,
            packet_count=200,
            rcvbuf_requests=[4096, 4 * 1024 * 1024],
        )
        tiers = {t["tier"]: t for t in res["tiers"]}
        assert tiers["a"]["kernel_overflow"] > 0
        assert tiers["b"]["kernel_overflow"] == 0
        assert all(t["reconciled"] for t in tiers.values())
        rec = res["recommendation"]
        assert rec["status"] == "recommended"
        assert rec["tier"] == "b"


# ---------------------------------------------------------------- 逐包判定与配置版本


class TestVerdicts:
    def test_threshold_verdicts_use_start_config(self, client):
        epoch = set_config(client, mode="normal", drop_threshold=100)
        res = run_drill(client, message_size=200, packet_count=30)

        assert res["config_epoch"] == epoch
        assert res["config"] == {"mode": "normal", "drop_threshold": 100}
        for t in res["tiers"]:
            assert t["received"] == 30
            assert t["passed"] == 0
            assert t["over_limit_dropped"] == 30
            assert t["disconnect_dropped"] == 0
            assert t["rule_dropped"] == 30
            assert all(p["verdict"] == "over_limit_drop" for p in t["packets"])
            # 逐包记录的配置版本就是演练开始时的版本
            assert all(p["config_epoch"] == epoch for p in t["packets"])

    def test_disconnect_verdicts(self, client):
        epoch = set_config(client, mode="disconnect")
        res = run_drill(client, packet_count=20)
        assert res["config_epoch"] == epoch
        for t in res["tiers"]:
            assert t["received"] == 20
            assert t["disconnect_dropped"] == 20
            assert t["passed"] == 0 and t["over_limit_dropped"] == 0
            assert all(p["verdict"] == "disconnect_drop" for p in t["packets"])

    def test_small_message_passes_threshold(self, client):
        set_config(client, mode="normal", drop_threshold=100)
        res = run_drill(client, message_size=28, packet_count=20)
        for t in res["tiers"]:
            assert t["passed"] == 20 and t["rule_dropped"] == 0


# ---------------------------------------------------------------- 入参校验


class TestValidation:
    def test_invalid_requests_return_422(self, client):
        base = {"message_size": 100, "packet_count": 10, "rcvbuf_requests": [4096, 8192]}
        bad = [
            {**base, "message_size": 27},          # 小于 MTUP 头长
            {**base, "message_size": 1401},        # 超过 1400
            {**base, "packet_count": 0},
            {**base, "packet_count": 4097},        # 超过 4096
            {**base, "rcvbuf_requests": [4096]},   # 只有一档
            {**base, "rcvbuf_requests": [4096, 8192, 16384]},  # 三档
            {**base, "rcvbuf_requests": [10, 20]},             # 低于下限
            {**base, "rcvbuf_requests": [4096, 999999999]},    # 高于上限
            {**base, "extra": 1},                  # 多余字段
        ]
        for body in bad:
            r = client.post("/rcvbuf/drill", json=body)
            assert r.status_code == 422, body

    def test_missing_fields_return_422(self, client):
        assert client.post("/rcvbuf/drill", json={}).status_code == 422


# ---------------------------------------------------------------- 并行与共存


class TestConcurrency:
    def test_parallel_drills_do_not_interfere(self, client):
        out: dict[str, dict] = {}

        def worker(name, **kw):
            out[name] = run_drill(client, **kw)

        threads = [
            threading.Thread(target=worker, args=("a",), kwargs={"packet_count": 30}),
            threading.Thread(
                target=worker,
                args=("b",),
                kwargs={"message_size": 200, "packet_count": 40,
                        "rcvbuf_requests": [131072, 262144]},
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        a, b = out["a"], out["b"]
        assert a["drill_id"] != b["drill_id"]
        assert a["packet_count"] == 30 and b["packet_count"] == 40
        for res in (a, b):
            for t in res["tiers"]:
                assert t["reconciled"] is True and t["unattributed"] == 0
                assert t["received"] == res["packet_count"]
                assert t["stray_datagrams"] == 0
            assert res["recommendation"]["status"] == "recommended"

    def test_probe_and_config_unaffected_by_drill(self, client):
        epoch_before = client.get("/echo/config").json()["epoch"]
        run_drill(client, packet_count=30)
        # 演练不改动回显配置
        assert client.get("/echo/config").json()["epoch"] == epoch_before
        # /probe 照常服务
        r = client.post("/probe", json={"timeout_ms": 150})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "ok"


class TestDocs:
    def test_drill_in_openapi(self, client):
        assert client.get("/docs").status_code == 200
        spec = client.get("/openapi.json").json()
        assert "/rcvbuf/drill" in spec["paths"]
