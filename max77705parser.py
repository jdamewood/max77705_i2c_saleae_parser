#!/usr/bin/env python3
"""
MAX77705 / MAX77804 I2C CSV Summary Parser
Corrected for MAX17050 fuel gauge with configurable sense resistor.
"""

import argparse
import csv
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ----------------------------------------------------------------------
# USER CONFIGURABLE: Sense resistor value in milliohms
# Common values: 10.0 mΩ (default), 5.0 mΩ, 7.5 mΩ, etc.
# This affects current, capacity, and charge counter calculations.
# ----------------------------------------------------------------------
SENSE_RESISTOR_MOHM = 10.0   # change this to match your hardware

# I2C block addresses (7‑bit)
I2C_BLOCKS = {
    0x25: "MUIC",
    0x36: "Fuel Gauge",
    0x62: "Debug",
    0x66: "PMIC",
    0x69: "Charger"
}

# ----------------------------------------------------------------------
# Helper decode functions for Fuel Gauge (MAX17050)
# ----------------------------------------------------------------------

def decode_status_reg(value):
    bits = {
        "POR": (value >> 0) & 1,
        "Imn": (value >> 1) & 1,
        "Imx": (value >> 2) & 1,
        "Vmn": (value >> 3) & 1,
        "Vmx": (value >> 4) & 1,
        "Tmn": (value >> 5) & 1,
        "Tmx": (value >> 6) & 1,
    }
    return f"Status: {', '.join(f'{k}={v}' for k, v in bits.items())}"

def decode_soc_status(raw):
    """
    MAX17050 SOC_STATUS register (0x04)
    High byte: SOC in 1/2% units (0‑200)
    Low byte: flags (RelDt2, DNR, EDet)
    """
    high = (raw >> 8) & 0xFF
    low = raw & 0xFF
    soc = high / 2.0
    flags = []
    if low & 0x80: flags.append("RelDt2")
    if low & 0x40: flags.append("DNR")
    else: flags.append("DataReady")
    if low & 0x20: flags.append("EDet")
    return f"SOC = {soc:.1f}%  Flags: {','.join(flags)}"

def decode_config_reg(raw):
    """CONFIG register (0x0C) for MAX17050"""
    sleep = (raw >> 8) & 0xFF
    alert = (raw >> 4) & 0x0F
    ath = (raw >> 3) & 0x01
    alert_type = "SOC change" if ath else "Voltage change"
    return f"Sleep={sleep}, Alert={alert}% ({alert_type})"

def decode_table_cmd(raw):
    """TABLE_CMD register (0x3E) – used to unlock OCV table"""
    if raw == 0x4A57:
        return "Unlock table (\"JW\")"
    mv = 319.5 + raw * 0.0703125
    return f"OCV = {mv:.1f} mV"

def scale_capacity(raw):
    """
    Capacity in mAh = raw * 0.5 * (10 / Rsense_mΩ)
    Because the internal calculation assumes 10 mΩ sense resistor.
    """
    return raw * 0.5 * (10.0 / SENSE_RESISTOR_MOHM)

def scale_current(raw):
    """
    Current in mA = signed(raw) * 1562500 / (Rsense_uΩ * gain)
    gain = 2 (default for 10 mΩ), but we simplify by using the Rsense factor.
    """
    val = raw if raw < 0x8000 else raw - 0x10000   # signed 16‑bit
    # The factor 1562500 comes from the driver; we multiply by (10/Rsense) to compensate.
    rsense_ratio = 10.0 / SENSE_RESISTOR_MOHM
    return val * 15625 * rsense_ratio / 1000   # result in mA

# ----------------------------------------------------------------------
# Fuel Gauge register map (MAX17050) – corrected for realistic decoding
# ----------------------------------------------------------------------

FUELGAUGE_REGISTERS = {
    0x00: ("STATUS_REG", None, (0, 0xFFFF), decode_status_reg),
    0x02: ("VCELL_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"Cell Voltage: {x * 0.078125:.2f} mV"),
    0x04: ("SOC_STATUS", (0, 100), (0, 0xFFFF), decode_soc_status),
    0x06: ("MODE_REG", None, (0, 0xFFFF), lambda x: f"Mode: 0x{x:04X}"),
    0x08: ("VERSION_REG", None, (0, 0xFFFF), lambda x: f"Version: 0x{x:04X}"),
    0x0A: ("HIBRT_REG", None, (0, 0xFFFF), lambda x: f"HibRt: 0x{x:04X}"),
    0x0C: ("CONFIG_REG", None, (0, 0xFFFF), decode_config_reg),
    0x0E: ("VALRT_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"Voltage Alert: {x * 0.078125:.2f} mV"),
    0x10: ("CRATE_REG", None, (-32768, 32767), lambda x: f"C/rate: {x * 0.20833:.1f}%"),
    0x14: ("TEST_REG", None, (0, 0xFFFF), lambda x: f"Test: 0x{x:04X}"),
    0x18: ("VRESET_ID_REG", None, (0, 0xFFFF), lambda x: f"VReset ID: 0x{x:04X}"),
    0x1A: ("TEMPERATURE_REG", (-20, 60), (0, 0xFFFF), lambda x: f"Temperature: {x / 10.0:.1f}°C"),   # correct
    0x3E: ("TABLE_CMD", None, (0, 0xFFFF), decode_table_cmd),

    # Additional MAX77705/MAX17050 registers (many are common)
    0x05: ("REMCAP_REP_REG", None, (0, 0xFFFF), lambda x: f"Reported Remaining Capacity: {scale_capacity(x):.1f} mAh"),
    0x06: ("SOCREP_REG", (0, 100), (0, 0xFFFF), lambda x: f"Reported SOC: {x / 256.0:.1f}%"),
    0x0D: ("SOCMIX_REG", (0, 100), (0, 0xFFFF), lambda x: f"Mixed SOC: {min(x / 256.0, 100):.1f}%"),
    0x0E: ("SOCAV_REG", (0, 100), (0, 0xFFFF), lambda x: f"Average SOC: {x / 256.0:.1f}%"),
    0x0F: ("REMCAP_MIX_REG", None, (0, 0xFFFF), lambda x: f"Mixed Remaining Capacity: {scale_capacity(x):.1f} mAh"),
    0x10: ("FULLCAP_REG", None, (0, 0xFFFF), lambda x: f"Full Capacity: {scale_capacity(x):.1f} mAh"),
    0x11: ("TIME_TO_EMPTY_REG", None, (0, 0xFFFF), lambda x: f"Time to Empty: {x * 5.625 / 3600:.2f} hours"),
    0x13: ("FULLSOCTHR_REG", None, (0, 0xFFFF), lambda x: f"Full SOC Threshold: {x / 256.0:.2f}%"),
    0x15: ("RFAST_REG", None, (0, 0xFFFF), lambda x: f"Fast Resistance: 0x{x:04X}"),
    0x16: ("AVR_TEMPERATURE_REG", (-20, 60), (0, 0xFFFF), lambda x: f"Avg Temperature: {((x >> 8) * 0.125) - 64:.1f}°C (Raw: 0x{x:04X})"),
    0x17: ("CYCLES_REG", (0, 1000), (0, 0xFFFF), lambda x: f"Cycle Count: {x / 256.0:.2f}"),
    0x18: ("DESIGNCAP_REG", None, (0, 0xFFFF), lambda x: f"Design Capacity: {scale_capacity(x):.1f} mAh"),
    0x19: ("AVR_VCELL_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"Avg Cell Voltage: {x * 0.078125:.2f} mV"),
    0x1D: ("CONFIG_REG2", None, (0, 0xFFFF), lambda x: f"Config2: 0x{x:04X}"),
    0x1E: ("ICHGTERM_REG", None, (0, 0xFFFF), lambda x: f"Charge Termination Current: {scale_current(x):.2f} mA"),
    0x1F: ("REMCAP_AV_REG", None, (0, 0xFFFF), lambda x: f"Avg Remaining Capacity: {scale_capacity(x):.2f} mAh"),
    0x23: ("FULLCAP_NOM_REG", None, (0, 0xFFFF), lambda x: f"Nominal Full Capacity: {scale_capacity(x):.1f} mAh"),
    0x2B: ("MISCCFG_REG", None, (0, 0xFFFF), lambda x: f"Misc Config: 0x{x:04X}"),
    0x35: ("FULLCAP_REP_REG", None, (0, 0xFFFF), lambda x: f"Reported Full Capacity: {scale_capacity(x):.1f} mAh"),
    0x43: ("ISYS_REG", (-3000, 3000), (-32768, 32767), lambda x: f"System Current: {scale_current(x):.2f} mA"),
    0x4B: ("AVGISYS_REG", (-3000, 3000), (-32768, 32767), lambda x: f"Avg System Current: {scale_current(x):.2f} mA"),
    0x4D: ("QH_REG", None, (-32768, 32767), lambda x: f"Charge Counter: {scale_current(x) * 0.36:.2f} mAh"),
    0xB1: ("VSYS_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"System Voltage: {x * 0.078125:.2f} mV"),
    0xB2: ("TALRTTH2_REG", None, (0, 0xFFFF), lambda x: f"Temp Alert Threshold 2: 0x{x:04X}"),
    0xB3: ("VBYP_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"Bypass Voltage: {x * 0.078125:.2f} mV"),
    0xBB: ("CONFIG2_REG", None, (0, 0xFFFF), lambda x: f"Config 2: Auto Discharge={((x >> 8) & 0x1)}"),
    0xFB: ("VFOCV_REG", (3000, 4500), (0, 0xFFFF), lambda x: f"Fuel Gauge OCV: {x * 0.078125:.2f} mV"),
}

# ----------------------------------------------------------------------
# PMIC, MUIC, Charger, Debug registers (unchanged from previous version)
# ----------------------------------------------------------------------

PMIC_REGISTERS = {
    0x00: ("PMICID1", None, (0, 0xFF), lambda x: f"PMIC ID: 0x{x:02X}"),
    0x01: ("PMICREV", None, (0, 0xFF), lambda x: f"PMIC Revision: 0x{x:02X}"),
    0x02: ("MAINCTRL1", None, (0, 0xFF), lambda x: f"Main Control: BiasEn={(x >> 7) & 1}"),
    0x22: ("INTSRC", None, (0, 0xFF), lambda x: f"Interrupt Source: {decode_intsrc(x)}"),
    0x23: ("INTSRC_MASK", None, (0, 0xFF), lambda x: f"Interrupt Source Mask: 0x{x:02X}"),
    0xF6: ("UNKNOWN", None, (0, 0xFF), lambda x: f"Unknown: 0x{x:02X}"),
}

MUIC_REGISTERS = {
    0x00: ("UIC_HW_REV", None, (0, 0xFF), lambda x: f"USBC HW Revision: 0x{x:02X}"),
    0x01: ("UIC_FW_REV", None, (0, 0xFF), lambda x: f"USBC FW Revision: 0x{x:02X}"),
    0x02: ("UIC_INT", None, (0, 0xFF), lambda x: f"USBC Interrupt: {decode_uic_int(x)}"),
    0x04: ("PD_INT", None, (0, 0xFF), lambda x: f"PD Interrupt: {decode_pd_int(x)}"),
    0x06: ("USBC_STATUS1", None, (0, 0xFF), lambda x: f"USBC Status 1: {decode_usbc_status1(x)}"),
    0x07: ("USBC_STATUS2", None, (0, 0xFF), lambda x: f"USBC Status 2: SysMsg=0x{x:02X}"),
    0x08: ("BC_STATUS", None, (0, 0xFF), lambda x: f"Battery Charge Status: {decode_bc_status(x)}"),
    0x09: ("UIC_FW_MINOR", None, (0, 0xFF), lambda x: f"USBC FW Minor: 0x{x:02X}"),
    0x0A: ("CC_STATUS0", None, (0, 0xFF), lambda x: f"CC Status 0: {decode_cc_status0(x)}"),
    0x0B: ("CC_STATUS1", None, (0, 0xFF), lambda x: f"CC Status 1: {decode_cc_status1(x)}"),
    0x0C: ("PD_STATUS0", None, (0, 0xFF), lambda x: f"PD Status 0: PDMsg=0x{x:02X}"),
    0x0D: ("PD_STATUS1", None, (0, 0xFF), lambda x: f"PD Status 1: {decode_pd_status1(x)}"),
    0x0E: ("UIC_INT_M", None, (0, 0xFF), lambda x: f"USBC Interrupt Mask: 0x{x:02X}"),
    0x0F: ("CC_INT_M", None, (0, 0xFF), lambda x: f"CC Interrupt Mask: 0x{x:02X}"),
    0x10: ("PD_INT_M", None, (0, 0xFF), lambda x: f"PD Interrupt Mask: 0x{x:02X}"),
    0x11: ("VDM_INT_M", None, (0, 0xFF), lambda x: f"VDM Interrupt Mask: 0x{x:02X}"),
    0x51: ("OPCODE_READ", None, (0, 0xFF), lambda x: f"Opcode Read: 0x{x:02X}"),
    0x52: ("OPCODE_DATA", None, (0, 0xFF), lambda x: f"Opcode Data: 0x{x:02X}"),
    0xF0: ("UNKNOWN", None, (0, 0xFF), lambda x: f"Unknown: 0x{x:02X}"),
    0x21: ("CONTROL1", None, (0, 0xFF), lambda x: f"Control 1: 0x{x:02X}"),
    0x22: ("CONTROL2", None, (0, 0xFF), lambda x: f"Control 2: 0x{x:02X}"),
    0x41: ("RESET", None, (0, 0xFF), lambda x: f"Reset: 0x{x:02X}"),
}

CHARGER_REGISTERS = {
    0x05: ("CHG_STATUS", None, (0, 0xFF), lambda x: f"Charger Status: 0x{x:02X}"),
    0x4A: ("INPUT_LIMIT", None, (0, 0xFF), lambda x: f"Input Limit: 0x{x:02X}"),
    0x59: ("THERMAL_STATUS", None, (0, 0xFF), lambda x: f"Thermal Status: 0x{x:02X}"),
    0x5B: ("CHARGE_CURRENT", None, (0, 0xFF), lambda x: f"Charge Current: 0x{x:02X}"),
    0x60: ("OTG_CONTROL", None, (0, 0xFF), lambda x: f"OTG Control: 0x{x:02X}"),
    0x61: ("VOLTAGE_CONTROL", None, (0, 0xFF), lambda x: f"Voltage Control: 0x{x:02X}"),
    0x66: ("TIMER_CONTROL", None, (0, 0xFF), lambda x: f"Timer Control: 0x{x:02X}"),
    0xB1: ("CHG_INT_MASK", None, (0, 0xFF), lambda x: f"Charger Interrupt Mask: {decode_chg_int_mask(x)}"),
    0xB2: ("CHG_INT_OK", None, (0, 0xFF), lambda x: f"Charger Interrupt OK: 0x{x:02X}"),
    0xB3: ("DETAILS_00", None, (0, 0xFF), lambda x: f"Charger Details 00: 0x{x:02X}"),
    0xB4: ("DETAILS_01", None, (0, 0xFF), lambda x: f"Charger Details 01: 0x{x:02X}"),
    0xB5: ("DETAILS_02", None, (0, 0xFF), lambda x: f"Charger Details 02: 0x{x:02X}"),
    0xB6: ("DTLS_03", None, (0, 0xFF), lambda x: f"Charger Details 03: 0x{x:02X}"),
    0xB7: ("CNFG_00", None, (0, 0xFF), lambda x: f"Charger Config 00: 0x{x:02X}"),
    0xB8: ("CNFG_01", None, (0, 0xFF), lambda x: f"Charger Config 01: 0x{x:02X}"),
    0xB9: ("CNFG_02", None, (0, 0xFF), lambda x: f"Charger Config 02: 0x{x:02X}"),
    0xBA: ("CNFG_03", None, (0, 0xFF), lambda x: f"Charger Config 03: 0x{x:02X}"),
    0xBB: ("CNFG_04", None, (0, 0xFF), lambda x: f"Charger Config 04: 0x{x:02X}"),
    0xBC: ("CNFG_05", None, (0, 0xFF), lambda x: f"Charger Config 05: 0x{x:02X}"),
    0xBD: ("CNFG_06", None, (0, 0xFF), lambda x: f"Charger Config 06: 0x{x:02X}"),
    0xBE: ("CNFG_07", None, (0, 0xFF), lambda x: f"Charger Config 07: 0x{x:02X}"),
    0xBF: ("CNFG_08", None, (0, 0xFF), lambda x: f"Charger Config 08: 0x{x:02X}"),
    0xC0: ("CNFG_09", None, (0, 0xFF), lambda x: f"Charger Config 09: 0x{x:02X}"),
    0xC1: ("CNFG_10", None, (0, 0xFF), lambda x: f"Charger Config 10: 0x{x:02X}"),
    0xC2: ("CNFG_11", None, (0, 0xFF), lambda x: f"Charger Config 11: 0x{x:02X}"),
    0xC3: ("CNFG_12", None, (0, 0xFF), lambda x: f"Charger Config 12: 0x{x:02X}"),
}

DEBUG_REGISTERS = {
    0x01: ("DEBUG_REG1", None, (0, 0xFF), lambda x: f"Debug Register 1: 0x{x:02X}"),
}

# Map block name to register dictionary
BLOCK_REGISTERS = {
    "Fuel Gauge": FUELGAUGE_REGISTERS,
    "PMIC": PMIC_REGISTERS,
    "MUIC": MUIC_REGISTERS,
    "Charger": CHARGER_REGISTERS,
    "Debug": DEBUG_REGISTERS,
}

# ----------------------------------------------------------------------
# Decoding helpers for MUIC, PMIC, Charger (unchanged)
# ----------------------------------------------------------------------

def decode_intsrc(value):
    bits = {
        "CHG": (value >> 0) & 1,
        "TOP": (value >> 1) & 1,
        "FG": (value >> 2) & 1,
        "USBC": (value >> 3) & 1,
    }
    return ' | '.join(k for k, v in bits.items() if v)

def decode_uic_int(value):
    bits = {
        "APCmdResI": (value >> 7) & 1,
        "SYSMsgI": (value >> 6) & 1,
        "VBusDetI": (value >> 5) & 1,
        "VbADCI": (value >> 4) & 1,
        "DCDTmoI": (value >> 3) & 1,
        "CHGTypI": (value >> 1) & 1,
        "UIDADCI": (value >> 0) & 1,
    }
    return ' | '.join(k for k, v in bits.items() if v)

def decode_pd_int(value):
    bits = {
        "PDMsgI": (value >> 7) & 1,
        "DataRole": (value >> 5) & 1,
        "SSAccI": (value >> 1) & 1,
        "FCTIDI": (value >> 0) & 1,
    }
    return ' | '.join(k for k, v in bits.items() if v)

def decode_usbc_status1(value):
    vbadc = (value >> 4) & 0xF
    uidadc = value & 0x7
    uidadc_str = {0: "GND", 3: "255Kohm", 4: "301Kohm", 5: "523Kohm", 6: "619Kohm", 7: "Open"}.get(uidadc, "Unknown")
    return f"VBADC=0x{vbadc:X}, UIDADC={uidadc_str}"

def decode_bc_status(value):
    vbus_det = (value >> 7) & 1
    chg_type = value & 0x3
    chg_type_str = {0: "Nothing", 1: "USB SDP", 2: "CDP", 3: "DCP"}.get(chg_type, "Unknown")
    return f"VBUS Detect={vbus_det}, Charge Type={chg_type_str}"

def decode_cc_status0(value):
    cc_pin_stat = (value >> 6) & 0x3
    cc_pin_stat_str = {
        0: "No Connection", 1: "Sink", 2: "Source", 3: "Audio Accessory",
        4: "Debug Accessory", 5: "Error", 6: "Disabled", 7: "RFU"
    }.get(cc_pin_stat, "Unknown")
    cc_stat = value & 0x7
    return f"CC Pin State={cc_pin_stat_str}, CC Status=0x{cc_stat:02X}"

def decode_cc_status1(value):
    vconn_ocp = (value >> 5) & 1
    vsafe0v = (value >> 3) & 1
    return f"VCONN OCP={vconn_ocp}, VSAFE0V={vsafe0v}"

def decode_pd_status1(value):
    data_role = (value >> 7) & 1
    psrdy = (value >> 4) & 1
    fct_id = value & 0xF
    return f"Data Role={'UFP' if data_role == 0 else 'DFP'}, PSRDY={psrdy}, FCT ID=0x{fct_id:X}"

def decode_chg_int_mask(value):
    bits = {
        "BYP_M": (value >> 0) & 1,
        "BST_M": (value >> 1) & 1,
        "CHG_M": (value >> 2) & 1,
        "WCIN_M": (value >> 3) & 1,
        "CHGIN_M": (value >> 4) & 1,
        "AICL_M": (value >> 5) & 1,
        "TOPOFF_M": (value >> 6) & 1,
        "OVP_M": (value >> 7) & 1,
    }
    lines = []
    for k, v in bits.items():
        if v == 0:
            lines.append(f"{k} unmasked → {k.replace('_M','')} interrupt enabled")
        else:
            lines.append(f"{k} masked → {k.replace('_M','')} interrupt disabled")
    return "<br>".join(lines)

# ----------------------------------------------------------------------
# CSV parsing and main
# ----------------------------------------------------------------------

def parse_csv(input_file):
    latest = defaultdict(dict)
    last_reg = {}
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        i = 0
        while i < len(rows):
            row = rows[i]
            if not row['Data'].strip():
                i += 1
                continue
            try:
                addr7 = int(row['Address'], 16)
                data = int(row['Data'], 16)
                rw = row['Read/Write'].strip().lower()
                block = I2C_BLOCKS.get(addr7, f"0x{addr7:02X}")
                block_regs = BLOCK_REGISTERS.get(block, {})
                # Special handling for Fuel Gauge 16‑bit reads
                if block == "Fuel Gauge" and rw == "read" and last_reg.get(block) in block_regs and i+1 < len(rows):
                    next_row = rows[i+1]
                    if next_row['Data'].strip():
                        data2 = int(next_row['Data'], 16)
                        raw = (data << 8) | data2
                        latest[block][last_reg[block]] = raw
                        i += 1  # skip the second byte row
                    else:
                        i += 1
                        continue
                else:
                    if rw == "write":
                        last_reg[block] = data
                    elif rw == "read" and last_reg.get(block) in block_regs:
                        latest[block][last_reg[block]] = data
            except (ValueError, KeyError) as e:
                print(f"Skipping row {i+2} due to error: {e} – row: {row}")
            i += 1
    return latest

def color_value(val, limits):
    if limits is None:
        return str(val)
    minv, maxv, _ = limits
    try:
        v = float(val)
    except:
        return str(val)
    if v < minv or v > maxv:
        return f"{Fore.RED}{val}{Style.RESET_ALL}"
    elif (v - minv) < 0.1 * (maxv - minv) or (maxv - v) < 0.1 * (maxv - minv):
        return f"{Fore.YELLOW}{val}{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}{val}{Style.RESET_ALL}"

def print_summary(data):
    for block in sorted(data.keys()):
        print(f"\n-------------------- {block} --------------------")
        print(f"{'Register':<10} | {'Name':<20} | {'Raw':<8} | Decoded")
        print("-" * 55)
        block_regs = BLOCK_REGISTERS.get(block, {})
        for reg in sorted(block_regs.keys()):
            if reg in data[block]:
                name, limits, _, decode = block_regs[reg]
                raw = data[block][reg]
                decoded = decode(raw)
                # Add warning for implausible capacity
                if block == "Fuel Gauge" and name in ("REMCAP_REP_REG", "FULLCAP_REG", "DESIGNCAP_REG"):
                    capacity = scale_capacity(raw)
                    if capacity > 6000:
                        decoded += f"  ⚠️ capacity {capacity:.0f} mAh exceeds typical range"
                print(f"{hex(reg):<10} | {name:<20} | {hex(raw):<8} | {decoded}")
            else:
                name, _, _, _ = block_regs[reg]
                print(f"{hex(reg):<10} | {name:<20} | {'----':<8} | (not read)")
        # Unknown registers found in data but not in map
        for reg in sorted(data[block].keys()):
            if reg not in block_regs:
                print(f"{hex(reg):<10} | {'(unknown)':<20} | {hex(data[block][reg]):<8} | (raw value)")

def main():
    parser = argparse.ArgumentParser(description="MAX77705/MAX77804 I2C CSV Summary Parser (corrected for MAX17050)")
    parser.add_argument('input_file', help='Saleae‑style CSV file')
    args = parser.parse_args()
    latest = parse_csv(args.input_file)
    print_summary(latest)

if __name__ == "__main__":
    main()