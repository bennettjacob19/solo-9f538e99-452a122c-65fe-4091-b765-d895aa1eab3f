"""UDP 接收缓冲区演练：确认调大 SO_RCVBUF 能否扛住短时停读。

场景：遥测网关短时停读后丢包，值班员需要证据来判断调大接收缓冲区是否有用。

演练流程（每次演练 = 两档对照）：
- 每档各建一对独立的本机 UDP 套接字：接收套接字设置该档 SO_RCVBUF，
  发送套接字把同一批 MTUP 报文（演练编号 + 序号）整批发往接收端，
  **整批发完才开始读**——复现"停读期间缓冲区被灌满"的过程；
- 两档共用演练开始时的回显配置（配置快照 + epoch），接收端每处理一条
  实收报文就记录其序号、实际使用的配置版本与判定
  （放行 / 断联丢弃 / 超限丢弃）；
- 排空后读取该接收套接字的内核丢弃计数（/proc/net/udp 的 drops 列，
  即 sk_drops 终值，减去演练前基线），与逐包记录、发送结果三方对账：
  ``发送成功 = 实收 + 内核溢出 + 未归因``；
- 两档都整批发出且对账无缺口时，推荐零溢出中实际缓冲区最小的一档；
  两档均溢出则报告均不足；发送失败或证据不全时给出原因，暂不推荐。

并行演练互不干扰：每次演练、每档都使用独立临时端口套接字，回显配置只在
演练开始时读取一次；结束或中断后各档套接字都在 finally 中关闭，不影响
回显端与 /probe 的正常服务。
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .echo_server import EchoConfig, EchoState
from .packets import HEADER_SIZE, build_packet, parse_packet

# 演练参数上限
MAX_MESSAGE_SIZE = 1400
MAX_PACKET_COUNT = 4096
MAX_RCVBUF_REQUEST = 64 * 1024 * 1024  # 64 MiB，超出此值的请求没有实际意义

# 本机环回时序常量
SETTLE_SECONDS = 0.1  # 整批发完后，等内核把环回包全部送入接收队列（或丢弃）
DRAIN_TIMEOUT_SECONDS = 0.3  # 排空：连续静默这么久视为已排空

Verdict = Literal["pass", "disconnect_drop", "over_limit_drop"]
TierName = Literal["a", "b"]

# ---------------------------------------------------------------------------
# API 模型
# ---------------------------------------------------------------------------


class DrillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message_size: int = Field(
        ..., ge=HEADER_SIZE, le=MAX_MESSAGE_SIZE,
        description="MTUP 报文长度（字节，28~1400）",
    )
    packet_count: int = Field(
        ..., ge=1, le=MAX_PACKET_COUNT,
        description="每档发送的报文数（1~4096）",
    )
    rcvbuf_requests: list[Annotated[int, Field(ge=256, le=MAX_RCVBUF_REQUEST)]] = Field(
        ..., min_length=2, max_length=2,
        description=(
            "两档 SO_RCVBUF 请求值（字节，每档 256~67108864）。"
            "内核通常按请求值翻倍生效并受 net.core.rmem_max 封顶，以返回的实际值为准"
        ),
    )


class PacketVerdict(BaseModel):
    seq: int = Field(..., description="实收报文的序号")
    config_epoch: int = Field(..., description="判定该包时实际使用的回显配置版本")
    verdict: Verdict = Field(
        ..., description="pass=放行；disconnect_drop=断联丢弃；over_limit_drop=超限丢弃"
    )


class TierResult(BaseModel):
    tier: TierName
    requested_rcvbuf: int = Field(..., description="本档 SO_RCVBUF 请求值（字节）")
    actual_rcvbuf: int = Field(
        ..., description="getsockopt(SO_RCVBUF) 实际生效值（内核通常翻倍并封顶 rmem_max）"
    )
    sent: int = Field(..., description="成功发出的包数")
    send_failures: int = Field(..., description="发送失败的包数")
    send_error: Optional[str] = Field(None, description="首次发送失败详情")
    received: int = Field(..., description="实收并判定有效的本演练报文数")
    passed: int = Field(..., description="判定为放行的包数")
    rule_dropped: int = Field(..., description="规则丢弃包数（断联丢弃 + 超限丢弃）")
    disconnect_dropped: int = Field(..., description="断联丢弃包数")
    over_limit_dropped: int = Field(..., description="超限丢弃包数")
    kernel_overflow: Optional[int] = Field(
        None,
        description="排空后接收套接字的内核丢弃计数终值（减去演练前基线）；计数不可读时为 null",
    )
    unattributed: Optional[int] = Field(
        None,
        description="发送成功但既未实收也未计入内核溢出的包数；对账无缺口时应为 0",
    )
    reconciled: bool = Field(..., description="对账是否无缺口（内核溢出计数可读且未归因为 0）")
    stray_datagrams: int = Field(0, description="收到的非本演练数据报数（已剔除，不参与对账）")
    packets: list[PacketVerdict] = Field(..., description="逐包判定记录")


class Recommendation(BaseModel):
    status: Literal["recommended", "insufficient", "unavailable"] = Field(
        ...,
        description=(
            "recommended=推荐某档；insufficient=两档均溢出、均不足；"
            "unavailable=发送失败或证据不全，暂不推荐"
        ),
    )
    tier: Optional[TierName] = Field(None, description="推荐的档位（recommended 时给出）")
    requested_rcvbuf: Optional[int] = Field(None, description="推荐档的 SO_RCVBUF 请求值")
    actual_rcvbuf: Optional[int] = Field(None, description="推荐档的实际缓冲区大小")
    reason: str = Field(..., description="推荐 / 均不足 / 暂不推荐的原因")


class DrillResult(BaseModel):
    drill_id: str
    message_size: int
    packet_count: int
    config_epoch: int = Field(..., description="演练开始时的回显配置版本（两档共用）")
    config: EchoConfig = Field(..., description="演练开始时的回显配置快照（两档共用）")
    tiers: list[TierResult] = Field(..., description="两档各自的演练与对账结果")
    recommendation: Recommendation
    started_at: datetime
    finished_at: datetime
    duration_ms: float


# ---------------------------------------------------------------------------
# 内核丢弃计数（/proc/net/udp 的 drops 列，即 sk_drops）
# ---------------------------------------------------------------------------

_SOCKET_LINK = re.compile(r"socket:\[(\d+)\]")


def _socket_inode(sock: socket.socket) -> Optional[int]:
    """取套接字 inode（用于在 /proc/net/udp 中精确匹配本套接字）。"""
    try:
        link = os.readlink(f"/proc/self/fd/{sock.fileno()}")
    except OSError:
        return None
    m = _SOCKET_LINK.fullmatch(link)
    return int(m.group(1)) if m else None


def _read_kernel_drops(*, inode: Optional[int], port: int) -> Optional[int]:
    """读取指定 UDP 套接字的内核丢弃计数。

    优先按 inode 精确匹配；inode 不可用（非 Linux 等）时按本机端口匹配
    （IPv4 套接字先查 /proc/net/udp，命中即返回，不会被 udp6 同端口干扰）。
    读不到返回 None（调用方按"证据不全"处理）。
    """
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path, "r", encoding="ascii") as fh:
                lines = fh.readlines()[1:]
        except OSError:
            continue
        port_hit: Optional[int] = None
        for line in lines:
            parts = line.split()
            # 列：sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ref pointer drops
            if len(parts) < 13:
                continue
            if inode is not None and parts[9] == str(inode):
                return int(parts[12])
            try:
                local_port = int(parts[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            if local_port == port:
                port_hit = int(parts[12])
        if port_hit is not None:
            return port_hit
    return None


# ---------------------------------------------------------------------------
# 演练引擎
# ---------------------------------------------------------------------------


def _classify(config: EchoConfig, size: int) -> Verdict:
    """按演练开始时的回显配置判定一条实收报文（与回显端规则一致）。"""
    if config.mode == "disconnect":
        return "disconnect_drop"
    if config.drop_threshold is not None and size > config.drop_threshold:
        return "over_limit_drop"
    return "pass"


def _recommend(tiers: list[TierResult]) -> Recommendation:
    problems: list[str] = []
    for t in tiers:
        if t.send_failures:
            detail = f"（首次失败：{t.send_error}）" if t.send_error else ""
            problems.append(f"档位 {t.tier} 有 {t.send_failures} 包发送失败{detail}")
        if t.kernel_overflow is None:
            problems.append(f"档位 {t.tier} 的内核溢出计数不可读")
        elif not t.reconciled:
            problems.append(f"档位 {t.tier} 对账缺口 {t.unattributed} 包")
    if problems:
        return Recommendation(
            status="unavailable",
            reason="；".join(problems) + "；证据不全，暂不推荐",
        )
    zero = [t for t in tiers if t.kernel_overflow == 0]
    if not zero:
        return Recommendation(
            status="insufficient",
            reason=(
                f"两档均整批发出且对账无缺口，但两档都发生内核溢出"
                f"（a 档 {tiers[0].kernel_overflow} 包、b 档 {tiers[1].kernel_overflow} 包），"
                "两档缓冲区均不足"
            ),
        )
    best = min(zero, key=lambda t: (t.actual_rcvbuf, t.requested_rcvbuf, t.tier))
    return Recommendation(
        status="recommended",
        tier=best.tier,
        requested_rcvbuf=best.requested_rcvbuf,
        actual_rcvbuf=best.actual_rcvbuf,
        reason=(
            "两档均整批发出且对账无缺口；"
            f"档位 {best.tier} 零内核溢出且实际缓冲区最小（{best.actual_rcvbuf} 字节）"
        ),
    )


class RcvbufDrill:
    """一次接收缓冲区演练。每个实例独立持有演练资源，并行演练互不干扰。"""

    def __init__(self, state: EchoState) -> None:
        self._state = state

    async def run(self, req: DrillRequest) -> DrillResult:
        started_at = datetime.now(timezone.utc)
        t0 = time.monotonic()
        # 演练开始时的回显配置：两档共用，演练期间不再读取，互不干扰
        config = self._state.config
        epoch = self._state.epoch
        drill_id = uuid.uuid4()

        # 阻塞型 socket 收发放进工作线程，事件循环（/probe 等）照常服务；
        # 协程被取消时线程内 finally 仍会关闭各档套接字，资源必定释放
        tiers = await asyncio.to_thread(self._run_tiers, drill_id, req, config, epoch)

        finished_at = datetime.now(timezone.utc)
        return DrillResult(
            drill_id=str(drill_id),
            message_size=req.message_size,
            packet_count=req.packet_count,
            config_epoch=epoch,
            config=config,
            tiers=tiers,
            recommendation=_recommend(tiers),
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=round((time.monotonic() - t0) * 1000.0, 3),
        )

    def _run_tiers(
        self, drill_id: uuid.UUID, req: DrillRequest, config: EchoConfig, epoch: int
    ) -> list[TierResult]:
        return [
            self._run_tier(drill_id, "a", req.rcvbuf_requests[0], req, config, epoch),
            self._run_tier(drill_id, "b", req.rcvbuf_requests[1], req, config, epoch),
        ]

    def _run_tier(
        self,
        drill_id: uuid.UUID,
        tier: TierName,
        requested: int,
        req: DrillRequest,
        config: EchoConfig,
        epoch: int,
    ) -> TierResult:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, requested)
            recv_sock.bind(("127.0.0.1", 0))
            actual = recv_sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            port = recv_sock.getsockname()[1]
            inode = _socket_inode(recv_sock)
            drops_before = _read_kernel_drops(inode=inode, port=port)

            # 发送：整批发完才开始读。发送失败逐包计数，继续发完剩余报文
            send_failures = 0
            send_error: Optional[str] = None
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                send_sock.connect(("127.0.0.1", port))
                for seq in range(1, req.packet_count + 1):
                    payload = build_packet(drill_id, seq, req.message_size)
                    try:
                        send_sock.send(payload)
                    except OSError as exc:
                        send_failures += 1
                        if send_error is None:
                            send_error = f"seq={seq}: {type(exc).__name__}: {exc}"
            finally:
                send_sock.close()

            # 等内核把环回包全部送入接收队列（或计入丢弃），再开始排空
            time.sleep(SETTLE_SECONDS)

            packets: list[PacketVerdict] = []
            stray = 0
            recv_sock.settimeout(DRAIN_TIMEOUT_SECONDS)
            for _ in range(req.packet_count + 1024):  # 防御性上限，正常在静默超时后退出
                try:
                    data = recv_sock.recv(65535)
                except (TimeoutError, BlockingIOError):
                    break
                pkt = parse_packet(data)
                if pkt is None or pkt.session_id != drill_id:
                    stray += 1
                    continue
                packets.append(
                    PacketVerdict(
                        seq=pkt.seq,
                        config_epoch=epoch,
                        verdict=_classify(config, len(data)),
                    )
                )

            # 排空后取该接收套接字的内核溢出终值
            drops_after = _read_kernel_drops(inode=inode, port=port)
        finally:
            recv_sock.close()

        sent = req.packet_count - send_failures
        received = len(packets)
        passed = sum(1 for p in packets if p.verdict == "pass")
        disconnect_dropped = sum(1 for p in packets if p.verdict == "disconnect_drop")
        over_limit_dropped = received - passed - disconnect_dropped
        if drops_before is not None and drops_after is not None:
            kernel_overflow: Optional[int] = drops_after - drops_before
            unattributed: Optional[int] = sent - received - kernel_overflow
            reconciled = unattributed == 0
        else:
            kernel_overflow = None
            unattributed = None
            reconciled = False
        return TierResult(
            tier=tier,
            requested_rcvbuf=requested,
            actual_rcvbuf=actual,
            sent=sent,
            send_failures=send_failures,
            send_error=send_error,
            received=received,
            passed=passed,
            rule_dropped=disconnect_dropped + over_limit_dropped,
            disconnect_dropped=disconnect_dropped,
            over_limit_dropped=over_limit_dropped,
            kernel_overflow=kernel_overflow,
            unattributed=unattributed,
            reconciled=reconciled,
            stray_datagrams=stray,
            packets=packets,
        )
