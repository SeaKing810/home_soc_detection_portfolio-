from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from .utils import parse_iso8601


@dataclass(frozen=True)
class NormalizedEvent:
    timestamp: datetime
    host: str
    event_type: str

    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None

    process_name: Optional[str] = None
    process_command_line: Optional[str] = None
    parent_process_name: Optional[str] = None

    raw: Dict[str, Any] = None  # type: ignore


def normalize_sysmon_like(event: Dict[str, Any]) -> NormalizedEvent:
    """
    Convert a Sysmon style event dict into a normalized event.

    This supports a small subset of common fields and keeps the full raw event.
    """
    ts = parse_iso8601(event.get("UtcTime", event.get("TimeCreated", "1970-01-01T00:00:00Z")))
    host = event.get("Computer", event.get("Host", "unknown"))

    # Our sample uses EventID values similar to Sysmon
    # 1: Process Create
    # 3: Network Connect
    # 4625: Failed logon (Windows Security style)
    event_id = str(event.get("EventID", "0"))

    if event_id == "1":
        return NormalizedEvent(
            timestamp=ts,
            host=host,
            event_type="process_create",
            user=event.get("User"),
            process_name=event.get("Image"),
            process_command_line=event.get("CommandLine"),
            parent_process_name=event.get("ParentImage"),
            raw=event,
        )

    if event_id == "3":
        dst_port = event.get("DestinationPort")
        try:
            dst_port_int = int(dst_port) if dst_port is not None else None
        except ValueError:
            dst_port_int = None

        return NormalizedEvent(
            timestamp=ts,
            host=host,
            event_type="network_connect",
            user=event.get("User"),
            src_ip=event.get("SourceIp"),
            dst_ip=event.get("DestinationIp"),
            dst_port=dst_port_int,
            process_name=event.get("Image"),
            process_command_line=event.get("CommandLine"),
            raw=event,
        )

    if event_id == "4625":
        dst_port = event.get("DestinationPort")
        try:
            dst_port_int = int(dst_port) if dst_port is not None else None
        except ValueError:
            dst_port_int = None

        return NormalizedEvent(
            timestamp=ts,
            host=host,
            event_type="failed_logon",
            user=event.get("TargetUserName") or event.get("User"),
            src_ip=event.get("IpAddress"),
            dst_port=dst_port_int,
            raw=event,
        )

    return NormalizedEvent(
        timestamp=ts,
        host=host,
        event_type="unknown",
        raw=event,
    )
