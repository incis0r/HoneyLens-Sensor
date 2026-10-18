"""Shared, bounded process state for the WBM and WebVisu decoy surfaces."""

from __future__ import annotations

import math
import threading
import time
from datetime import UTC, datetime
from typing import Any

from . import identity as wago_identity


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


class DeviceState:
    """A deterministic tank/pump process with a WAGO-like controller identity."""

    def __init__(self, unit_id: int = 1, identity: dict[str, Any] | None = None):
        self._lock = threading.RLock()
        self._started = time.monotonic()
        self._last_tick = self._started
        # Model identity — fixed, because it describes the product rather than the
        # unit, and the detection rules key on the order number.
        self.product = "WAGO 750-8202 PFC200 CS 2ETH RS"
        self.order_number = "750-8202"
        self.firmware = "02.01.10(02)"
        self.runtime_license = "CODESYS Runtime"

        # Unit identity — unique per deployment. See honeypots/wago/identity.py: the
        # values that came with the source captures belong to real third-party
        # controllers and must never be served from our sensors.
        ident = identity or wago_identity.generate()
        self.identity = ident
        self.serial = ident["serial"]
        self.hostname = ident["hostname"]
        self.mac = ident["mac"]
        self.ip_address = ident["ip_address"]
        self.netmask = ident["netmask"]
        self.gateway = ident["gateway"]
        self.ntp_server = ident["ntp_server"]
        self.snmp_location = ident["snmp_location"]
        self.rx_packets_base = ident["rx_packets_base"]
        self.tx_packets_base = ident["tx_packets_base"]
        self.unit_id = max(1, min(247, int(unit_id)))
        self.plc_state = "RUN"
        self.modbus_enabled = True
        self.snmp_enabled = True
        self.display_on = True
        self.cleanmode = False
        self.default_webserver = "Webserver"
        self.coils: list[bool] = [False] * 128
        self.discrete_inputs: list[bool] = [False] * 128
        self.holding: list[int] = [0] * 128
        self.input_registers: list[int] = [0] * 128
        self.holding[0] = 650  # tank setpoint: 65.0%
        self.holding[1] = 250  # outlet valve: 25.0%
        self.holding[2] = 900  # high alarm: 90.0%
        self.coils[0] = True  # pump
        self.coils[2] = True  # automatic mode
        self.tank_level = ident["tank_level"]
        self.temperature = ident["temperature"]
        self.pressure = ident["pressure"]
        self.flow = ident["flow"]
        self.reset_count = 0
        self.config_generation = 1
        self.users = {"admin": "Administrator", "user": "Operator"}
        self.task_cycles = list(ident["task_cycles"])

    def _tick_locked(self) -> None:
        now = time.monotonic()
        dt = min(max(now - self._last_tick, 0.0), 10.0)
        self._last_tick = now
        running = self.plc_state == "RUN"
        pump = bool(self.coils[0]) and running
        auto = bool(self.coils[2]) and running
        valve = _clamp(self.holding[1] / 10.0, 0.0, 100.0)
        setpoint = _clamp(self.holding[0] / 10.0, 0.0, 100.0)

        if auto:
            if self.tank_level < setpoint - 2.0:
                pump = True
            elif self.tank_level > setpoint + 2.0:
                pump = False
            self.coils[0] = pump

        inlet = 18.0 if pump else 0.0
        outlet = valve * 0.12
        self.flow = max(0.0, inlet - outlet)
        self.tank_level = _clamp(self.tank_level + (inlet - outlet) * dt / 180.0, 0.0, 100.0)
        target_temp = 24.5 if pump else 22.0
        self.temperature += (target_temp - self.temperature) * min(dt / 120.0, 1.0)
        self.temperature += math.sin(now / 45.0) * 0.002
        self.pressure = _clamp(1.05 + (1.55 if pump else 0.0) - valve * 0.004, 0.0, 4.0)

        high_alarm = self.tank_level >= _clamp(self.holding[2] / 10.0, 0.0, 100.0)
        self.discrete_inputs[0] = self.tank_level < 10.0
        self.discrete_inputs[1] = high_alarm
        self.discrete_inputs[2] = running
        self.discrete_inputs[3] = pump

        runtime = int(now - self._started)
        self.input_registers[0] = round(self.temperature * 10) & 0xFFFF
        self.input_registers[1] = round(self.tank_level * 10) & 0xFFFF
        self.input_registers[2] = round(self.pressure * 100) & 0xFFFF
        self.input_registers[3] = round(self.flow * 10) & 0xFFFF
        self.input_registers[4] = (runtime >> 16) & 0xFFFF
        self.input_registers[5] = runtime & 0xFFFF
        self.input_registers[6] = 1 if high_alarm else 0
        if running:
            for index in range(len(self.task_cycles)):
                self.task_cycles[index] += int(dt * (50 if index == 2 else 125))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._tick_locked()
            return {
                "product": self.product,
                "order_number": self.order_number,
                "firmware": self.firmware,
                "runtime_license": self.runtime_license,
                "hostname": self.hostname,
                "mac": self.mac,
                "serial": self.serial,
                "ntp_server": self.ntp_server,
                "snmp_location": self.snmp_location,
                "rx_packets_base": self.rx_packets_base,
                "tx_packets_base": self.tx_packets_base,
                "ip_address": self.ip_address,
                "netmask": self.netmask,
                "gateway": self.gateway,
                "unit_id": self.unit_id,
                "plc_state": self.plc_state,
                "modbus_enabled": self.modbus_enabled,
                "snmp_enabled": self.snmp_enabled,
                "display_on": self.display_on,
                "cleanmode": self.cleanmode,
                "default_webserver": self.default_webserver,
                "pump_command": self.coils[0],
                "pump": self.coils[0] and self.plc_state == "RUN",
                "automatic": self.coils[2],
                "setpoint": self.holding[0] / 10.0,
                "valve": self.holding[1] / 10.0,
                "high_alarm_limit": self.holding[2] / 10.0,
                "tank_level": round(self.tank_level, 1),
                "temperature": round(self.temperature, 1),
                "pressure": round(self.pressure, 2),
                "flow": round(self.flow, 1),
                "low_alarm": self.discrete_inputs[0],
                "high_alarm": self.discrete_inputs[1],
                "runtime_seconds": int(time.monotonic() - self._started),
                "reset_count": self.reset_count,
                "config_generation": self.config_generation,
                "task_cycles": list(self.task_cycles),
                "local_time": datetime.now(UTC).strftime("%H:%M:%S"),
                "local_date": datetime.now(UTC).strftime("%d.%m.%Y"),
            }

    def read_bits(self, kind: str, address: int, quantity: int) -> list[bool]:
        with self._lock:
            self._tick_locked()
            source = self.coils if kind == "coil" else self.discrete_inputs
            if address < 0 or quantity < 1 or address + quantity > len(source):
                raise IndexError("bit address out of range")
            return list(source[address : address + quantity])

    def read_registers(self, kind: str, address: int, quantity: int) -> list[int]:
        with self._lock:
            self._tick_locked()
            source = self.holding if kind == "holding" else self.input_registers
            if address < 0 or quantity < 1 or address + quantity > len(source):
                raise IndexError("register address out of range")
            return list(source[address : address + quantity])

    def write_coils(self, address: int, values: list[bool]) -> None:
        with self._lock:
            if address < 0 or not values or address + len(values) > len(self.coils):
                raise IndexError("coil address out of range")
            for offset, value in enumerate(values):
                self.coils[address + offset] = bool(value)
            self.config_generation += 1
            self._tick_locked()

    def write_registers(self, address: int, values: list[int]) -> None:
        with self._lock:
            if address < 0 or not values or address + len(values) > len(self.holding):
                raise IndexError("register address out of range")
            for offset, value in enumerate(values):
                self.holding[address + offset] = max(0, min(0xFFFF, int(value)))
            self.holding[0] = min(self.holding[0], 1000)
            self.holding[1] = min(self.holding[1], 1000)
            self.holding[2] = min(self.holding[2], 1000)
            self.config_generation += 1
            self._tick_locked()

    def set_plc_state(self, state: str) -> None:
        value = state.upper()
        if value not in ("RUN", "STOP"):
            raise ValueError("invalid PLC state")
        with self._lock:
            self.plc_state = value
            self.config_generation += 1

    def reset(self) -> None:
        with self._lock:
            self.plc_state = "STOP"
            self.coils[0] = False
            self.reset_count += 1
            self.config_generation += 1
            self._last_tick = time.monotonic()

    def update_network(self, hostname: str, ip_address: str, netmask: str, gateway: str) -> None:
        with self._lock:
            self.hostname = hostname[:63]
            self.ip_address = ip_address
            self.netmask = netmask
            self.gateway = gateway
            self.config_generation += 1
