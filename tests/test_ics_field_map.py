"""Per-protocol field map: each ICS decoy's own vocabulary onto the ics_events columns.

The defect this pins: the table's columns were modelled on Modbus, so the ingest had no
way to carry IEC-104's type_id/common_address/ioa (and six more dialects) and dropped them.
"""

from honeylens.ingest.ics_helpers import ICS_FIELD_MAP, map_protocol_fields


def test_modbus_fills_the_columns_the_table_was_designed_for():
    out = map_protocol_fields(
        "modbus",
        {
            "fc": 3,
            "fc_name": "Read Holding Registers",
            "unit_id": 1,
            "address": 0,
            "quantity": 4,
            "pdu_hex": "0300000004",
        },
    )
    assert out == {
        "function_code": 3,
        "function_name": "Read Holding Registers",
        "unit_id": 1,
        "register_start": 0,
        "register_count": 4,
        "data_value": "0300000004",
    }


def test_iec104_speaks_its_own_vocabulary():
    """type_id is the function code, common_address the device, ioa the register."""
    out = map_protocol_fields(
        "iec104",
        {
            "type_id": 100,
            "type_name": "C_IC_NA_1",
            "common_address": 65535,
            "ioa": 0,
            "asdu_hex": "6401",
        },
    )
    assert out["function_code"] == 100 and out["device_address"] == "65535"
    assert out["register_start"] == 0 and out["data_value"] == "6401"


def test_dnp3_station_address_is_the_device():
    out = map_protocol_fields(
        "dnp3",
        {
            "fc": 23,
            "fc_name": "Disable Unsolicited",
            "station_address": 10,
            "app_objects_hex": "3c02",
        },
    )
    assert out == {
        "function_code": 23,
        "function_name": "Disable Unsolicited",
        "device_address": "10",
        "data_value": "3c02",
    }


def test_bacnet_service_is_the_function():
    out = map_protocol_fields(
        "bacnet", {"service": 12, "service_name": "ReadProperty", "apdu_hex": "0102"}
    )
    assert out == {"function_code": 12, "function_name": "ReadProperty", "data_value": "0102"}


def test_opcua_service_id_is_the_function():
    out = map_protocol_fields(
        "opcua", {"service_id": 428, "service_name": "GetEndpoints", "body_hex": "aa"}
    )
    assert out == {"function_code": 428, "function_name": "GetEndpoints", "data_value": "aa"}


def test_enip_command_is_the_function():
    out = map_protocol_fields("enip", {"command": 513, "rule": "ListIdentity", "data_hex": "00"})
    assert out == {"function_code": 513, "function_name": "ListIdentity", "data_value": "00"}


def test_fins_mrc_is_the_function():
    out = map_protocol_fields(
        "fins", {"mrc": 5, "mrc_src_name": "Controller Data Read", "frame_hex": "80"}
    )
    assert out == {"function_code": 5, "function_name": "Controller Data Read", "data_value": "80"}


def test_mqtt_topic_is_the_device_and_message_the_data():
    out = map_protocol_fields(
        "mqtt", {"pkt_type": 3, "topic": "plant/line1", "rule": "publish", "message": "on"}
    )
    assert out == {
        "function_code": 3,
        "function_name": "publish",
        "device_address": "plant/line1",
        "data_value": "on",
    }


def test_modbus_prefers_the_written_value_over_the_raw_pdu():
    out = map_protocol_fields("modbus", {"value": "1", "pdu_hex": "deadbeef"})
    assert out["data_value"] == "1"


def test_a_decoy_with_no_entry_maps_nothing():
    """s7comm, mms, profinet and fox parse no protocol; that is correct, not a bug."""
    for hp in ("s7comm", "mms", "profinet", "fox"):
        assert hp not in ICS_FIELD_MAP
        assert map_protocol_fields(hp, {"bytes": 26, "route": "s7"}) == {}


def test_missing_and_null_fields_are_simply_absent():
    """iec104 sends null type_id/common_address/ioa on real rows."""
    out = map_protocol_fields(
        "iec104", {"type_id": None, "common_address": None, "ioa": None, "asdu_hex": "00"}
    )
    assert out == {"data_value": "00"}


def test_a_value_of_the_wrong_type_does_not_reach_an_integer_column():
    """Review Focus 1."""
    assert "function_code" not in map_protocol_fields("modbus", {"fc": "three"})
    assert map_protocol_fields("modbus", {"fc": "3"})["function_code"] == 3
    assert "function_code" not in map_protocol_fields("modbus", {"fc": True})
    assert "function_code" not in map_protocol_fields("modbus", {"fc": 3.5})


def test_an_out_of_range_integer_becomes_absent_rather_than_an_error():
    """Attacker-chosen numbers are arbitrary; quantity=33792 occurs in the window."""
    assert map_protocol_fields("modbus", {"quantity": 33792})["register_count"] == 33792
    assert "register_count" not in map_protocol_fields("modbus", {"quantity": 2**40})
    assert "register_count" not in map_protocol_fields("modbus", {"quantity": 2**31})
    assert map_protocol_fields("modbus", {"quantity": 2**31 - 1})["register_count"] == 2**31 - 1
    # Same rule for digit strings; a 5000-digit one used to raise ValueError out of int().
    assert "function_code" not in map_protocol_fields("modbus", {"fc": "9" * 5000})
    assert "function_code" not in map_protocol_fields("modbus", {"fc": "99999999999"})
    assert map_protocol_fields("modbus", {"fc": "0003"})["function_code"] == 3


def test_an_over_long_text_value_is_truncated_not_dropped():
    """Review Focus 4: device_address and function_name are VARCHAR(64) and the MQTT
    topic is attacker-chosen. The untruncated value stays in ics_events.metadata."""
    out = map_protocol_fields("mqtt", {"topic": "a" * 200, "rule": "b" * 200})
    assert len(out["device_address"]) == 64
    assert len(out["function_name"]) == 64


def test_data_value_is_not_truncated():
    assert len(map_protocol_fields("modbus", {"pdu_hex": "ab" * 5000})["data_value"]) == 10000
