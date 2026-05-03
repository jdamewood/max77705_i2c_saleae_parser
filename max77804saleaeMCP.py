#!/usr/bin/env python3
"""
MAX77705 I2C Protocol Analyzer for Saleae Logic Analyzer (macOS)

================================================================================
DESCRIPTION
================================================================================
This script provides comprehensive decoding and analysis of I2C transactions
for the Maxim MAX77705 Power Management IC (PMIC) and associated peripherals.
It interfaces with Saleae Logic 2 software via the MCP (Model Context Protocol)
server to capture and decode I2C traffic in real-time or from saved captures.

================================================================================
SUPPORTED DEVICES
================================================================================
The parser decodes the following I2C devices (7-bit addresses):
- 0x25: MUIC (USB-C Controller) - Status, interrupt, and configuration registers
- 0x36: Fuel Gauge (MAX17050) - Battery voltage, current, temperature, SOC
- 0x48: Unknown/Undocumented device - Currently under analysis
- 0x66: PMIC (MAX77705) - Power management, charging, flash/torch control
- 0x69: Charger IC - Charging status and configuration
- 0x4A: RGB LED Controller - LED brightness, ramp, and blink patterns

================================================================================
SYSTEM REQUIREMENTS
================================================================================
Hardware:
- Saleae Logic Analyzer (any model with I2C support)
- Target device with MAX77705 or compatible PMIC

Software:
- macOS 10.15+ (Catalina or newer)
- Saleae Logic 2.x (https://www.saleae.com/downloads/)
- Python 3.7+ with the following packages:
  - requests (HTTP client for MCP communication)
  - pandas (CSV data processing)
  - matplotlib (optional, for plotting)
  - colorama (ANSI color support)

================================================================================
INSTALLATION (macOS)
================================================================================
1. Install Saleae Logic 2 from: https://www.saleae.com/downloads/

2. Install Python dependencies:
   $ pip3 install requests pandas matplotlib colorama

3. Clone or download this script to your local machine

4. Ensure the MCP server is running in Saleae Logic:
   - Open Saleae Logic 2
   - Go to Extensions > MCP Server
   - Verify server is running on http://127.0.0.1:10530

================================================================================
HARDWARE SETUP
================================================================================
1. Connect Saleae Logic Analyzer to your Mac via USB

2. Connect logic analyzer probes to your target device:
   - Channel 0: I2C SCL (PMIC bus)
   - Channel 1: I2C SDA (PMIC bus)
   - Channel 2: I2C SCL (Fuel gauge bus)
   - Channel 3: I2C SDA (Fuel gauge bus)

3. Configure I2C analyzers in Saleae Logic:
   - Add I2C analyzer for PMIC (SCL=0, SDA=1)
   - Add I2C analyzer for Fuel Gauge (SCL=2, SDA=3)

4. Start capture in Saleae Logic or load existing .sal file

================================================================================
USAGE
================================================================================
Basic usage (analyze existing capture):
   $ python3 max77804saleaeMCP.py

The script will:
1. Connect to Saleae MCP server
2. Load the specified capture file
3. Add I2C analyzers for each bus
4. Export CSV data and parse transactions
5. Decode register values with bitmap interpretation
6. Generate color-coded terminal output
7. Save decoded transactions to CSV
8. Generate activity plots (if matplotlib installed)

================================================================================
CONFIGURATION
================================================================================
Edit these variables at the top of the script:

MCP_URL = "http://127.0.0.1:10530"  # Saleae MCP server address
CAPTURE_FILE = r"path/to/your/capture.sal"  # Path to .sal file

BUSES = [
    ("PMIC", 1, 0),   # (bus_name, SDA_channel, SCL_channel)
    ("FUEL", 3, 2),
]

KNOWN_ADDRESSES = {
    "66": "PMIC",
    "36": "FUEL",
    "25": "MUIC",
    "69": "CHARGER",
    "48": "RGB_LED",
    "XX": "UNKNOWN",  # Add custom addresses as needed
}

================================================================================
OUTPUT FILES
================================================================================
The script generates the following output files in the current directory:

- decoded_transactions.csv: Complete list of all decoded transactions
- unknown_addresses.csv: Summary of unknown I2C addresses detected
- device_activity.png: Bar chart of transaction counts by device

================================================================================
TROUBLESHOOTING (macOS)
================================================================================

Issue: "Failed to load capture"
Solution:
- Verify capture file path is correct
- Ensure file has .sal extension
- Check file permissions: $ ls -la your_file.sal

Issue: "Connection refused" to MCP server
Solution:
- Open Saleae Logic 2
- Go to Extensions > MCP Server > Start
- Verify server is running: $ curl http://127.0.0.1:10530

Issue: "No valid I2C transactions found"
Solution:
- Check probe connections
- Verify I2C analyzer channel assignments
- Ensure capture includes I2C activity

Issue: Python package not found
Solution:
- Use pip3 instead of pip: $ pip3 install requests
- Or use virtual environment: $ python3 -m venv venv

================================================================================
DECODING FEATURES
================================================================================

PMIC (0x66) Registers Decoded:
- CHG_INT, CHG_INT_OK: Charger interrupt status with bitmap decoding
- CHG_CNFG_00-14: Charger configuration (current, voltage, timers)
- LSCNFG: Flash and torch current control
- INTSRC: Interrupt source identification

MUIC (0x25) Registers Decoded:
- STATUS1-3: USB-C connection state, VBUS detection
- INTMASK1-3: Interrupt mask configuration
- CDETCTRL1: Charger detection control
- CTRL1-4: MUX and ADC configuration

Fuel Gauge (0x36) Registers Decoded:
- VCELL: Battery voltage (mV)
- SOC_STATUS: State of charge with flags
- CONFIG: Sleep and alert configuration
- TEMPERATURE: Battery temperature (°C)
- STATUS: DQ, VX, LF flags

================================================================================
EXTENDING THE PARSER
================================================================================
To add support for new registers or devices:

1. Add register definitions to the appropriate REGS dictionary
2. Create decode function following the existing pattern
3. Add entry to device_stats for new device type
4. Update KNOWN_ADDRESSES with the I2C address

Example for new register:
    "XX": ("REG_NAME", lambda x: f"Decoded: {x}")

================================================================================
KNOWN ISSUES
================================================================================
- Address 0x48 appears active but is undocumented - under investigation
- Some I2C reads without preceding writes show "??" for register
- Capture with very high bus speeds may miss some transactions

================================================================================
LICENSE
================================================================================
MIT License - Free for personal and commercial use

================================================================================
AUTHOR
================================================================================
James Damewood / Organization
Last Updated: 2026

================================================================================
SEE ALSO
================================================================================
- MAX77705 Datasheet (Maxim Integrated)
- MAX17050 Datasheet (Fuel Gauge)
- Saleae Logic 2 Documentation: https://support.saleae.com/
- I2C Protocol Specification
"""
import requests
import json
import os
import time
import tempfile
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict  # Add this line

# Add colorama for Windows ANSI color support
try:
    import colorama
    colorama.init()
except ImportError:
    pass

# Update COLORS dictionary to include UNKNOWN
COLORS = {
    'PMIC': '\033[92m',    # Green
    'MUIC': '\033[93m',    # Yellow
    'FUEL': '\033[96m',    # Cyan
    'CHARGER': '\033[95m', # Magenta
    'UNKNOWN': '\033[91m', # Red - ADD THIS LINE
    'RESET': '\033[0m'     # Reset to default
}

MCP_URL = "http://127.0.0.1:10530"
CAPTURE_FILE = r"/home/james/Documents/SM-G900v/SM-G900V_PMIC_FUEL_I2C5.sal"

# Known I2C addresses (7-bit) for MAX77705
# Known I2C addresses (7-bit) for MAX77705
KNOWN_ADDRESSES = {
    "66": "PMIC",
    "36": "FUEL",
    "25": "MUIC",
    "69": "CHARGER",
    "4A": "RGB_LED",
    "48": "RGB_LED",  # Add this line - observed address
    "62": "DEBUG",
}

# Bus definitions: (name, SDA channel, SCL channel)
BUSES = [
    ("PMIC", 1, 0),
    ("FUEL", 3, 2),
]

# ----------------------------------------------------------------------
# Register maps with bitmap decoding
# ----------------------------------------------------------------------

# Charger Interrupt Bit Definitions (from max77705-private.h)
CHG_INT_BITS = {
    0x01: "BYP_I (Bypass Mode Interrupt)",
    0x02: "INP_LIMIT_I (Input Current Limit Interrupt)",
    0x04: "BATP_I (Battery Temperature Interrupt)",
    0x08: "BAT_I (Battery Status Interrupt)",
    0x10: "CHG_I (Charging Interrupt)",
    0x20: "WCIN_I (Wireless Charger Input Interrupt)",
    0x40: "CHGIN_I (Charger Input Interrupt)",
    0x80: "AICL_I (Auto Input Current Limit Interrupt)"
}

CHG_INT_OK_BITS = {
    0x01: "BYP_OK (Bypass Ready)",
    0x02: "DISQBAT_OK (Discharge Battery OK)",
    0x04: "BATP_OK (Battery Temperature OK)",
    0x08: "BAT_OK (Battery OK)",
    0x10: "CHG_OK (Charging OK)",
    0x20: "WCIN_OK (Wireless Input OK)",
    0x40: "CHGIN_OK (Charger Input OK)",
    0x80: "AICL_OK (Auto Input Current Limit OK)"
}

# Charger Details Register Bit Definitions
CHG_DTLS_00_BITS = {
    0x01: "BATP_DTLS (Battery Temp Details)",
    0x18: "WCIN_DTLS (Wireless Input Details)",
    0x60: "CHGIN_DTLS (Charger Input Details)"
}

CHG_DTLS_01_BITS = {
    0x0F: "CHG_DTLS (Charger Details)",
    0x70: "BAT_DTLS (Battery Details)"
}

PMIC_REGS = {
    "00": "IFLASH", "01": "RESERVED_01", "02": "ITORCH",
    "03": "ITORCHTORCHTIMER", "04": "FLASH_TIMER", "05": "FLASH_EN",
    "06": "MAX_FLASH1", "07": "MAX_FLASH2", "08": "MAX_FLASH3",
    "09": "MAX_FLASH4", "0A": "VOUT_CNTL", "0B": "VOUT_FLASH",
    "0E": "FLASH_INT", "0F": "FLASH_INT_MASK", "10": "FLASH_INT_STATUS",
    "20": "PMIC_ID1", "21": "PMIC_ID2", "22": "INTSRC",
    "23": "INTSRC_MASK", "24": "TOPSYS_INT", "26": "TOPSYS_INT_MASK",
    "28": "TOPSYS_STAT", "2A": "MAINCTRL1", "2B": "LSCNFG",
    "B0": "CHG_INT", "B1": "CHG_INT_MASK", "B2": "CHG_INT_OK",
    "B3": "CHG_DTLS_00", "B4": "CHG_DTLS_01", "B5": "CHG_DTLS_02",
    "B6": "CHG_DTLS_03", "B7": "CHG_CNFG_00", "B8": "CHG_CNFG_01",
    "B9": "CHG_CNFG_02", "BA": "CHG_CNFG_03", "BB": "CHG_CNFG_04",
    "BC": "CHG_CNFG_05", "BD": "CHG_CNFG_06", "BE": "CHG_CNFG_07",
    "BF": "CHG_CNFG_08", "C0": "CHG_CNFG_09", "C1": "CHG_CNFG_10",
    "C2": "CHG_CNFG_11", "C3": "CHG_CNFG_12", "C4": "CHG_CNFG_13",
    "C5": "CHG_CNFG_14", "C6": "SAFEOUT_CTRL",
}

MUIC_REGS = {
    "00": "ID", "01": "STATUS1", "02": "STATUS2",
    "03": "STATUS3", "04": "INTMASK1", "05": "INTMASK2",
    "06": "INTMASK3", "07": "CDETCTRL1", "08": "CDETCTRL2",
    "09": "CTRL1", "0A": "CTRL2", "0B": "CTRL3",
    "0C": "CTRL4", "0D": "RESERVED", "0E": "RESERVED",
    "0F": "RESERVED", "10": "RESERVED", "11": "RESERVED",
    "12": "RESERVED", "13": "RESERVED", "14": "RESERVED",
    "15": "RESERVED", "16": "CTRL4", "41": "RESET_REG"
}

FG_REGS = {
    "00": "VCELL_RAW", "02": "VCELL", "04": "SOC_STATUS",
    "06": "MODE", "08": "VERSION", "0A": "HIBRT",
    "0C": "CONFIG", "0E": "VALRT", "10": "CRATE",
    "14": "TEST", "18": "VRESET_ID", "1A": "TEMPERATURE",
    "3C": "COMMAND", "3E": "TABLE_CMD", "40": "MODEL_DATA",
    "44": "SOC_STATUS", "50": "MODEL_DATA2", "5C": "CONFIG_DATA",
    "60": "MODEL_DATA3", "70": "MODEL_DATA4", "80": "MODEL_DATA5",
    "90": "MODEL_DATA6", "97": "RSENSE_VAL", "BD": "STATUS",
    "F3": "CHIP_ID",
}

# 16-bit registers for MAX17050 (2 bytes)
FG_16BIT_REGS = {"02", "04", "0C", "0E", "1A", "3E", "BD", "F3"}


# ----------------------------------------------------------------------
# Enhanced Decoding Functions
# ----------------------------------------------------------------------

def decode_chg_int(value):
    """Decode Charger Interrupt Register (0xB0)"""
    active = []
    for bit, name in CHG_INT_BITS.items():
        if value & bit:
            active.append(name)
    return f"Interrupts: {', '.join(active) if active else 'None'} (0x{value:02X})"


def decode_chg_int_ok(value):
    """Decode Charger Interrupt OK Register (0xB2)"""
    status = []
    for bit, name in CHG_INT_OK_BITS.items():
        if value & bit:
            status.append(name)
    return f"Status OK: {', '.join(status) if status else 'None'} (0x{value:02X})"


def decode_chg_dtls_00(value):
    """Decode Charger Details 00 Register (0xB3)"""
    batp = (value & 0x01)
    wcin = (value & 0x18) >> 3
    chgin = (value & 0x60) >> 5

    wcin_str = {0: "No Wireless", 1: "Wireless Detected", 2: "Wireless Active", 3: "Wireless Fault"}.get(wcin,
                                                                                                         "Unknown")
    chgin_str = {0: "No Input", 1: "USB Input", 2: "Adapter Input", 3: "Invalid"}.get(chgin, "Unknown")

    return f"BATP={batp}, WCIN={wcin_str}, CHGIN={chgin_str} (0x{value:02X})"


def decode_chg_dtls_01(value):
    """Decode Charger Details 01 Register (0xB4)"""
    chg_dtls = value & 0x0F
    bat_dtls = (value & 0x70) >> 4

    chg_str = {
        0: "No Charging",
        1: "Pre-charge",
        2: "Fast Charge CC",
        3: "Fast Charge CV",
        4: "Top-off",
        5: "Charge Done",
        6: "Charge Timer Fault",
        7: "Charge Suspend"
    }.get(chg_dtls, "Unknown")

    bat_str = {
        0: "Normal",
        1: "Over Voltage",
        2: "Under Voltage",
        3: "Over Current",
        4: "Short Circuit",
        5: "Over Temperature",
        6: "Open Circuit",
        7: "Unknown Fault"
    }.get(bat_dtls, "Unknown")

    return f"CHG={chg_str}, BAT={bat_str} (0x{value:02X})"


def decode_chg_dtls_02(value):
    """Decode Charger Details 02 Register (0xB5)"""
    bypass = value & 0x0F
    bypass_str = {
        0x00: "Normal Operation",
        0x01: "Bypass Mode Step 1",
        0x02: "Bypass Mode Step 2",
        0x03: "Bypass Mode Step 3",
        0x04: "Bypass Mode Step 4",
        0x05: "Bypass Mode Step 5",
        0x06: "Bypass Mode Step 6",
        0x07: "Bypass Mode Step 7",
        0x08: "Bypass Mode Step 8 (Full Bypass)"
    }.get(bypass, f"Bypass Level {bypass}")

    return f"Bypass: {bypass_str} (0x{value:02X})"

# Add optional decoder for address 0x48 if it follows MUIC register map
def decode_rgb_led(reg, val, is_read=False):
    """
    Decode RGB LED Controller (address 0x48/0x4A) transactions

    Register map based on max77705-private.h:
        0x30: LEDEN     - LED enable register
        0x31: LED0BRT   - LED0 brightness (0-255)
        0x32: LED1BRT   - LED1 brightness (0-255)
        0x33: LED2BRT   - LED2 brightness (0-255)
        0x34: LED3BRT   - LED3 brightness (0-255)
        0x36: LEDRMP    - LED ramp rate control
        0x38: LEDBLNK   - LED blink control
    """
    # Observed register being written in your logs
    if reg == "02":
        if val == 0xC2:
            return "RGB_LED: Enable LED0+LED1 (mid brightness - 0xC2)"
        elif val == 0x82:
            return "RGB_LED: Enable LED1 only (mid brightness - 0x82)"
        elif val == 0x02:
            return "RGB_LED: Enable LED1 only (low brightness - 0x02)"
        else:
            return f"RGB_LED: Write 0x{val:02X} to register 0x{reg}"

    # Standard RGB LED registers
    elif reg == "30":
        # LEDEN - Bitmap: bit0=LED0, bit1=LED1, bit2=LED2, bit3=LED3
        leds = []
        if val & 0x01: leds.append("LED0")
        if val & 0x02: leds.append("LED1")
        if val & 0x04: leds.append("LED2")
        if val & 0x08: leds.append("LED3")
        return f"RGB_LED: LEDEN = 0x{val:02X} ({', '.join(leds) if leds else 'All disabled'})"

    elif reg == "31":
        brightness = (val * 100) // 255
        return f"RGB_LED: LED0 brightness = {val} (0x{val:02X}) - {brightness}%"

    elif reg == "32":
        brightness = (val * 100) // 255
        return f"RGB_LED: LED1 brightness = {val} (0x{val:02X}) - {brightness}%"

    elif reg == "33":
        brightness = (val * 100) // 255
        return f"RGB_LED: LED2 brightness = {val} (0x{val:02X}) - {brightness}%"

    elif reg == "34":
        brightness = (val * 100) // 255
        return f"RGB_LED: LED3 brightness = {val} (0x{val:02X}) - {brightness}%"

    elif reg == "36":
        return f"RGB_LED: LEDRMP = 0x{val:02X} (ramp rate control)"

    elif reg == "38":
        return f"RGB_LED: LEDBLNK = 0x{val:02X} (blink control)"

    # Unknown register
    else:
        if is_read:
            return f"RGB_LED: Read 0x{val:02X} from register 0x{reg}"
        else:
            return f"RGB_LED: Write 0x{val:02X} to register 0x{reg}"


def decode_pmic_write(reg, val):
    """Enhanced PMIC register decoding with bitmap support"""
    # Add validation at the start
    if reg is None or reg == "??" or reg == "NAN" or reg == "None" or not reg:
        return None

    try:
        reg_int = int(reg, 16)
    except (ValueError, TypeError):
        return None

    # Now proceed with the rest of your existing code
    if reg == "B0":  # CHG_INT
        return decode_chg_int(val)
    elif reg == "B2":  # CHG_INT_OK
        return decode_chg_int_ok(val)
    elif reg == "B3":  # CHG_DTLS_00
        return decode_chg_dtls_00(val)
    elif reg == "B4":  # CHG_DTLS_01
        return decode_chg_dtls_01(val)
    elif reg == "B5":  # CHG_DTLS_02
        return decode_chg_dtls_02(val)
    elif reg == "B7":  # CHG_CNFG_00
        chg = (val >> 0) & 1
        otg = (val >> 1) & 1
        buck = (val >> 2) & 1
        boost = (val >> 3) & 1
        mode = val & 0x0F
        mode_names = {0: "MANUAL", 1: "CHG_ON", 2: "OTG", 3: "BUCK", 4: "BOOST"}
        mode_str = mode_names.get(mode, f"MODE={mode}")
        status = []
        if chg: status.append("CHG enabled")
        if otg: status.append("OTG mode")
        if buck: status.append("BUCK enabled")
        if boost: status.append("BOOST enabled")
        status_str = ", ".join(status) if status else "all disabled"
        return f"CHG_CNFG_00: {mode_str} ({status_str})"
    elif reg == "B8":  # CHG_CNFG_01
        timer = val & 0x03
        restart = (val >> 4) & 0x03
        timer_str = ["Disable", "4h", "6h", "8h"][timer]
        restart_str = ["100mV", "150mV", "200mV", "300mV"][restart]
        return f"CHG_CNFG_01: Timer={timer_str}, Restart threshold={restart_str}"
    elif reg == "B9":  # CHG_CNFG_02
        current = (val & 0x7F) * 40
        return f"CHG_CNFG_02: {current} mA charge current"
    elif reg == "BB":  # CHG_CNFG_04
        cv = val & 0x1F
        if cv == 0x1C:
            mv = 4340
        else:
            mv = (cv * 25) + 3650
        return f"CHG_CNFG_04: {mv} mV charge voltage"
    elif reg == "BD":  # CHG_CNFG_06
        unlock = (val >> 2) & 0x03
        return "CHG_CNFG_06: Unlocked" if unlock == 0x03 else "CHG_CNFG_06: Locked"
    elif reg == "C0":  # CHG_CNFG_09
        ma = val * 25
        return f"CHG_CNFG_09: {ma} mA input current limit"
    elif reg == "C6":  # SAFEOUT_CTRL
        discharge = (val >> 4) & 0x03
        return "SAFEOUT_CTRL: No active discharge" if discharge == 0 else f"SAFEOUT_CTRL: Active discharge (0x{val:02X})"
    elif reg == "2B":  # LSCNFG
        flash_cur = (val >> 0) & 0x0F
        torch_cur = (val >> 4) & 0x0F
        if flash_cur == 0 and torch_cur == 0:
            return "LSCNFG: Flash and Torch disabled"
        return f"LSCNFG: Flash={flash_cur * 50}mA, Torch={torch_cur * 12.5:.0f}mA"
    elif reg == "22":  # INTSRC
        srcs = []
        if val & 0x01: srcs.append("CHG")
        if val & 0x02: srcs.append("TOP")
        if val & 0x04: srcs.append("FG")
        if val & 0x08: srcs.append("USB")
        return f"INTSRC: {', '.join(srcs) if srcs else 'None'} (0x{val:02X})"

    return None

def decode_fuel_value(reg, raw_16bit):
    """Decode MAX17050 register value from 16-bit raw."""
    if reg == "02" or reg == "0E":  # VCELL or VALRT
        mv = 319.5 + raw_16bit * 0.0703125
        return f"{mv:.1f} mV"

    elif reg == "04":  # SOC_STATUS
        high_byte = (raw_16bit >> 8) & 0xFF
        flags = raw_16bit & 0xFF
        soc = high_byte // 2
        flag_desc = []
        if flags & 0x80:
            flag_desc.append("RelDt2")
        if flags & 0x40:
            flag_desc.append("DNR")
        else:
            flag_desc.append("DataReady")
        if flags & 0x20:
            flag_desc.append("EDet")
        return f"SOC = {soc}% (flags: {','.join(flag_desc)})"

    elif reg == "0C":  # CONFIG
        sleep = (raw_16bit >> 8) & 0xFF
        alert = (raw_16bit >> 4) & 0x0F
        ath = (raw_16bit >> 3) & 0x01
        alert_type = "SOC change" if ath else "Voltage change"
        return f"CONFIG: Sleep={sleep}, Alert={alert}% ({alert_type})"

    elif reg == "1A":  # TEMPERATURE
        temp = raw_16bit / 10.0
        return f"{temp:.1f}°C"

    elif reg == "3E":  # TABLE_CMD
        if raw_16bit == 0x4A57:
            return "Unlock table (\"JW\")"
        mv = 319.5 + raw_16bit * 0.0703125
        return f"OCV = {mv:.1f} mV"

    elif reg == "BD":  # STATUS
        flags = []
        if raw_16bit & 0x80:
            flags.append("DQ")
        if raw_16bit & 0x40:
            flags.append("VX")
        if raw_16bit & 0x10:
            flags.append("LF")
        return f"STATUS: {' | '.join(flags) if flags else 'stable'}"

    elif reg == "F3":  # CHIP_ID
        return f"CHIP_ID: 0x{raw_16bit:04X} (MAX17050)"

    else:
        return f"0x{raw_16bit:04X}"


def decode_muic_read(reg, val):
    if reg == "01":
        attached = val & 0x07
        attached_map = {0: "No device", 1: "USB device", 2: "Charger", 3: "USB+Charger",
                        4: "Audio", 5: "Audio+USB", 6: "Unknown", 7: "Unknown"}
        return f"STATUS1: {attached_map[attached]}"
    elif reg == "02":
        vb_present = "VBUS present" if (val & 0x40) else "VBUS absent"
        chg_det = "Charger detected" if (val & 0x01) else "No charger"
        return f"STATUS2: {chg_det}, {vb_present}"
    elif reg == "03":
        ovp = "OVP!" if (val & 0x80) else "OVP OK"
        return f"STATUS3: {ovp}"
    elif reg == "41":  # Reset register
        return f"RESET_REG: 0x{val:02X} (Write to reset)"
    return None


def decode_muic_write(reg, val):
    if reg == "04":
        enabled = [f"IRQ{i}" for i in range(8) if not ((val >> i) & 1)]
        return f"INTMASK1: {','.join(enabled) if enabled else 'All masked'} enabled"
    elif reg == "05":
        enabled = [f"IRQ{i + 8}" for i in range(8) if not ((val >> i) & 1)]
        return f"INTMASK2: {','.join(enabled) if enabled else 'All masked'} enabled"
    elif reg == "07":
        chgdeten = (val >> 0) & 1
        chgtypm = (val >> 1) & 1
        dchktm = (val >> 4) & 1
        return f"CDETCTRL1: CHGDET={'En' if chgdeten else 'Dis'}abled, CHGTYP={'MUIC' if chgtypm else 'Manual'}, DCHK={'Fast' if dchktm else 'Slow'}"
    elif reg == "09":
        comn1sw = val & 0x07
        comp2sw = (val >> 3) & 0x07
        com_str = ["Open", "USB", "Audio", "UART", "USB_CP", "UART_CP", "Reserved", "Reserved"]
        return f"CTRL1: D+={com_str[comn1sw]}, D-={com_str[comp2sw]}"
    elif reg in ("0C", "16"):
        adcmode = (val >> 6) & 0x03
        mode_str = ["Always on", "Always on+1M", "One shot", "2s pulse"][adcmode]
        return f"CTRL4: Mode={mode_str}"
    elif reg == "41":  # Reset register
        return f"RESET_REG: 0x{val:02X} (MUIC Reset)"
    return None


# ----------------------------------------------------------------------
# MCP Helper Functions
# ----------------------------------------------------------------------

def call_mcp_tool(tool_name, arguments=None, request_id=1):
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}}
    }
    resp = requests.post(MCP_URL, json=payload, timeout=60)
    return resp.json()


def load_capture(filepath):
    result = call_mcp_tool("load_capture", {"filepath": filepath})
    capture_id = None
    content = result.get("result", {}).get("content", [])
    for item in content:
        if item.get("type") == "text":
            try:
                data = json.loads(item["text"])
                capture_id = data.get("captureId")
            except:
                pass
    return capture_id


def add_analyzer(capture_id, sda, scl):
    result = call_mcp_tool("add_analyzer", {
        "captureId": capture_id,
        "analyzerName": "I2C",
        "settings": {"SDA": {"numberValue": sda}, "SCL": {"numberValue": scl}}
    })
    analyzer_id = None
    content = result.get("result", {}).get("content", [])
    for item in content:
        if item.get("type") == "text":
            try:
                data = json.loads(item["text"])
                analyzer_id = data.get("analyzerId")
            except:
                pass
    return analyzer_id


def export_csv_to_file(capture_id, analyzer_id, filepath):
    result = call_mcp_tool("legacy_export_analyzer", {
        "captureId": capture_id,
        "analyzerId": analyzer_id,
        "filepath": filepath,
        "radixType": 3
    })
    time.sleep(1)
    return "error" not in result and os.path.exists(filepath)


def parse_csv(filepath):
    """Parse Saleae CSV export, auto-detect column names."""
    df = pd.read_csv(filepath)

    # Auto-detect column names (Saleae uses different formats)
    col_map = {}
    for col in df.columns:
        col_lower = col.lower().strip()
        if 'time' in col_lower:
            col_map['time'] = col
        elif 'address' in col_lower:
            col_map['address'] = col
        elif 'data' in col_lower:
            col_map['data'] = col
        elif 'read' in col_lower or 'read/write' in col_lower:
            col_map['read'] = col

    # Fallback to expected names if detection fails
    time_col = col_map.get('time', 'Time [s]')
    addr_col = col_map.get('address', 'Address')
    data_col = col_map.get('data', 'Data')
    read_col = col_map.get('read', 'Read/Write')

    transactions = []
    current_time = None
    current_addr = None
    current_is_read = None
    current_data = []

    for _, row in df.iterrows():
        time_val = float(row[time_col])
        addr_str = str(row[addr_col]).replace('0x', '').upper()
        data_str = str(row[data_col]).replace('0x', '').upper()
        rw = str(row[read_col]).upper()
        is_read = (rw == 'READ')

        if current_addr is None:
            current_time = time_val
            current_addr = addr_str
            current_is_read = is_read
            current_data = [data_str]
        elif current_addr == addr_str and current_is_read == is_read:
            current_data.append(data_str)
        else:
            if current_data:
                transactions.append((current_time, current_addr, current_is_read, current_data.copy()))
            current_time = time_val
            current_addr = addr_str
            current_is_read = is_read
            current_data = [data_str]

    if current_data:
        transactions.append((current_time, current_addr, current_is_read, current_data))

    return transactions


def print_summary(all_transactions, unknown_addresses, reg_ptr, device_stats):
    """Print comprehensive summary including unknown address analysis"""

    print("\n" + "=" * 100)
    print(f"{COLORS['PMIC']}I2C TRANSACTION SUMMARY REPORT{COLORS['RESET']}")
    print("=" * 100)

    # Overall statistics
    total_transactions = len(all_transactions)
    read_count = sum(1 for _, _, is_read, _ in all_transactions if is_read)
    write_count = total_transactions - read_count

    print(f"\n📊 OVERALL STATISTICS:")
    print(f"   Total Transactions: {total_transactions}")
    print(f"   Write Operations: {write_count} ({write_count / total_transactions * 100:.1f}%)")
    print(f"   Read Operations: {read_count} ({read_count / total_transactions * 100:.1f}%)")

    # Device activity summary
    print(f"\n📱 DEVICE ACTIVITY:")
    for device, stats in sorted(device_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        color = COLORS.get(device, COLORS['UNKNOWN'])
        print(f"   {color}{device:<10}{COLORS['RESET']}: {stats['count']:4d} transactions "
              f"(Reads: {stats['reads']:3d}, Writes: {stats['writes']:3d})")

    # Unknown Address Analysis
    if unknown_addresses:
        print(f"\n⚠️  {COLORS['UNKNOWN']}UNKNOWN ADDRESS DETECTION{COLORS['RESET']}")
        print(f"   Found {len(unknown_addresses)} unknown I2C addresses in capture")
        print("   " + "-" * 50)

        for addr, info in sorted(unknown_addresses.items(), key=lambda x: x[1]['count'], reverse=True):
            print(f"\n   Address: 0x{addr}")
            print(f"     - Transactions: {info['count']}")
            print(f"     - Reads: {info['reads']}, Writes: {info['writes']}")
            print(f"     - First seen: {info['first_seen']:.6f}s")
            print(f"     - Last seen: {info['last_seen']:.6f}s")

            # Show register accesses if any
            if info.get('registers'):
                reg_list = list(info['registers'])[:5]
                print(f"     - Registers accessed: {', '.join(f'0x{r}' for r in reg_list)}")
                if len(info['registers']) > 5:
                    print(f"       ... and {len(info['registers']) - 5} more")

            # Show data values if any
            if info.get('data_values'):
                unique_values = sorted(info['data_values'])[:5]
                print(f"     - Data values seen: {', '.join(f'0x{v:02X}' for v in unique_values)}")
                if len(info['data_values']) > 5:
                    print(f"       ... and {len(info['data_values']) - 5} more")
    else:
        print(f"\n✅ No unknown I2C addresses detected - all traffic matches known devices")

    # Register pointer summary
    if reg_ptr:
        print(f"\n📝 LAST REGISTER ACCESSED PER ADDRESS:")
        for addr, last_reg in sorted(reg_ptr.items()):
            dev = KNOWN_ADDRESSES.get(addr, "UNKNOWN")
            print(f"   Address 0x{addr} ({dev}): Last register = 0x{last_reg}")

    # Timing analysis
    if all_transactions:
        first_time = all_transactions[0][0]
        last_time = all_transactions[-1][0]
        duration = last_time - first_time
        print(f"\n⏱️  TIMING ANALYSIS:")
        print(f"   Capture start: {first_time:.6f}s")
        print(f"   Capture end: {last_time:.6f}s")
        print(f"   Duration: {duration:.3f}s")
        if duration > 0:
            print(f"   Transaction rate: {total_transactions / duration:.2f} transactions/second")

    print("\n" + "=" * 100)


# ----------------------------------------------------------------------
# Main processing
# ----------------------------------------------------------------------

# Fix the main processing loop - ensure proper address mapping

def main():
    print(f"🔍 Processing {CAPTURE_FILE}...")
    capture_id = load_capture(CAPTURE_FILE)
    if capture_id is None:
        print("❌ Failed to load capture")
        return
    print(f"✅ Capture ID: {capture_id}")

    all_transactions = []
    decoded_entries = []
    reg_ptr = {}
    device_stats = defaultdict(lambda: {'count': 0, 'reads': 0, 'writes': 0})
    unknown_addresses = defaultdict(lambda: {
        'count': 0, 'reads': 0, 'writes': 0,
        'first_seen': None, 'last_seen': None,
        'registers': set(), 'data_values': set()
    })

    for bus_name, sda, scl in BUSES:
        print(f"\n🔧 Adding {bus_name} analyzer (SDA={sda}, SCL={scl})...")
        analyzer_id = add_analyzer(capture_id, sda, scl)
        if analyzer_id is None:
            print(f"   ❌ Failed to add {bus_name} analyzer")
            continue
        print(f"   ✅ Analyzer ID: {analyzer_id}")
        time.sleep(2)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            tmp_path = tmp.name

        if not export_csv_to_file(capture_id, analyzer_id, tmp_path):
            print(f"   ❌ Failed to export {bus_name} CSV")
            os.unlink(tmp_path)
            continue

        print(f"   ✅ Exported {bus_name} CSV ({os.path.getsize(tmp_path)} bytes)")
        bus_transactions = parse_csv(tmp_path)

        for ts, addr, is_read, data_bytes in bus_transactions:
            dev = KNOWN_ADDRESSES.get(addr, "UNKNOWN")

            # Update device statistics
            device_stats[dev]['count'] += 1
            if is_read:
                device_stats[dev]['reads'] += 1
            else:
                device_stats[dev]['writes'] += 1

            # Track unknown addresses
            if dev == "UNKNOWN":
                info = unknown_addresses[addr]
                info['count'] += 1
                if is_read:
                    info['reads'] += 1
                else:
                    info['writes'] += 1
                if info['first_seen'] is None or ts < info['first_seen']:
                    info['first_seen'] = ts
                if info['last_seen'] is None or ts > info['last_seen']:
                    info['last_seen'] = ts
                if not is_read and len(data_bytes) > 0:
                    try:
                        info['registers'].add(data_bytes[0])
                    except:
                        pass
                for data in data_bytes:
                    if data and data != '':
                        try:
                            info['data_values'].add(int(data, 16))
                        except:
                            pass

        all_transactions.extend(bus_transactions)
        os.unlink(tmp_path)
        print(f"   ✅ {len(bus_transactions)} transactions from {bus_name}")

    if not all_transactions:
        print("❌ No transactions found")
        return

    all_transactions.sort(key=lambda x: x[0])

    print("\n" + "=" * 120)
    print(f"DECODED TRANSACTIONS")
    print("=" * 120)
    print(f"{'TIME':<12} | {'ADDR':<6} | {'BUS':<10} | {'OP':<5} | {'REG':<6} | {'DATA':<12} | {'DECODED':<70}")
    print("-" * 140)

    for ts, addr_hex, is_read, data_bytes in all_transactions:
        dev = KNOWN_ADDRESSES.get(addr_hex, "UNKNOWN")
        # Safe color retrieval with fallback
        color = COLORS.get(dev, COLORS.get('UNKNOWN', '\033[91m'))
        reset = COLORS['RESET']
        addr_display = f"0x{addr_hex}"

        if is_read:
            reg = reg_ptr.get(addr_hex, "??")

            if reg == "??":
                desc = f"Read from unknown register (no preceding write)"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | READ | {reg:<6} | {'':<12} | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'READ', 'reg': reg, 'value': desc})
                continue

            if dev == "FUEL":
                if len(data_bytes) >= 2:
                    raw_value = (int(data_bytes[0], 16) << 8) | int(data_bytes[1], 16)
                else:
                    raw_value = int(data_bytes[0], 16)
                desc = decode_fuel_value(reg, raw_value)
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | READ | {reg:<6} | 0x{raw_value:04X}    | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'READ', 'reg': reg, 'value': desc})


            elif dev == "PMIC":
                # PMIC registers are 8-bit
                val = int(data_bytes[0], 16)
                # Only attempt to decode if register is valid
                if reg and reg != "??" and reg != "NAN" and reg != "None":
                    special = decode_pmic_write(reg, val)
                    if special:
                        desc = special
                    else:
                        reg_name = PMIC_REGS.get(reg, f"Reg 0x{reg}")
                        desc = f"{reg_name} = 0x{val:02X}"
                else:
                    desc = f"PMIC register read: 0x{val:02X} (unknown register - no preceding write)"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | READ | {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'READ', 'reg': reg, 'value': desc})

            elif dev == "MUIC":
                val = int(data_bytes[0], 16)
                desc = decode_muic_read(reg, val) or f"{MUIC_REGS.get(reg, f'Reg 0x{reg}')} = 0x{val:02X}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | READ | {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'READ', 'reg': reg, 'value': desc})


            else:  # UNKNOWN device
                val = int(data_bytes[0], 16) if data_bytes else 0
                # Special handling for address 0x48 (RGB LED)
                if addr_hex == "48":
                    desc = decode_rgb_led(reg, val, is_read=True)
                else:
                    desc = f"Unknown device (0x{addr_hex}) register 0x{reg} read: 0x{val:02X}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | READ | {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'READ', 'reg': reg, 'value': desc})
        else:
            # Write transaction
            reg = data_bytes[0]
            operands = data_bytes[1:] if len(data_bytes) > 1 else []
            reg_ptr[addr_hex] = reg
            if dev == "FUEL":
                if len(operands) >= 2 and reg in FG_16BIT_REGS:
                    raw_value = (int(operands[0], 16) << 8) | int(operands[1], 16)
                    desc = decode_fuel_value(reg, raw_value)
                    ops_str = f"0x{raw_value:04X}"
                else:
                    ops_str = ' '.join(operands[:4])
                    desc = f"Reg 0x{reg}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | WRITE| {reg:<6} | {ops_str:<12} | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'WRITE', 'reg': reg, 'value': desc})

            elif dev == "PMIC":
                val = int(operands[0], 16) if operands else 0
                special = decode_pmic_write(reg, val)
                if special:
                    desc = special
                else:
                    desc = f"{PMIC_REGS.get(reg, f'Reg 0x{reg}')} = 0x{val:02X}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | WRITE| {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'WRITE', 'reg': reg, 'value': desc})

            elif dev == "MUIC":
                val = int(operands[0], 16) if operands else 0
                special = decode_muic_write(reg, val)
                if special:
                    desc = special
                else:
                    desc = f"{MUIC_REGS.get(reg, f'Reg 0x{reg}')} = 0x{val:02X}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | WRITE| {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'WRITE', 'reg': reg, 'value': desc})



            else:  # UNKNOWN device
                val = int(operands[0], 16) if operands else 0
                # Special handling for address 0x48 (RGB LED)
                if addr_hex == "48":
                    desc = decode_rgb_led(reg, val, is_read=False)
                else:
                    desc = f"Unknown device (0x{addr_hex}) writing to reg 0x{reg} = 0x{val:02X}"
                print(
                    f"{ts:<12.6f} | {addr_display:<6} | {color}{dev:<10}{reset} | WRITE| {reg:<6} | 0x{val:02X}      | {desc}")
                decoded_entries.append(
                    {'time': ts, 'address': addr_hex, 'bus': dev, 'type': 'WRITE', 'reg': reg, 'value': desc})

    # Print summary after processing
    print_summary(all_transactions, unknown_addresses, reg_ptr, device_stats)

    # Export decoded CSV
    decoded_df = pd.DataFrame(decoded_entries)
    decoded_df.to_csv("decoded_transactions.csv", index=False)
    print("\n📄 Decoded transactions saved to 'decoded_transactions.csv'")

    # Export unknown addresses CSV for analysis
    if unknown_addresses:
        unknown_df = pd.DataFrame([{
            'address': addr,
            'count': info['count'],
            'reads': info['reads'],
            'writes': info['writes'],
            'first_seen': info['first_seen'],
            'last_seen': info['last_seen'],
            'registers': ', '.join(info['registers']) if info['registers'] else '',
            'data_values': ', '.join(f'0x{v:02X}' for v in sorted(info['data_values'])[:10]) if info[
                'data_values'] else ''
        } for addr, info in unknown_addresses.items()])
        unknown_df.to_csv("unknown_addresses.csv", index=False)
        print(f"📄 Unknown address details saved to 'unknown_addresses.csv'")

    # Plotting
    try:
        dev_counts = decoded_df['bus'].value_counts()
        plt.figure(figsize=(10, 6))
        colors_list = []
        for dev in dev_counts.index:
            if dev == 'PMIC':
                colors_list.append('green')
            elif dev == 'MUIC':
                colors_list.append('gold')
            elif dev == 'FUEL':
                colors_list.append('cyan')
            elif dev == 'UNKNOWN':
                colors_list.append('red')
            else:
                colors_list.append('gray')

        dev_counts.plot(kind='bar', color=colors_list)
        plt.title('Transaction Count by Device', fontsize=14)
        plt.xlabel('Device', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("device_activity.png", dpi=150)
        print("📊 Device activity plot saved to 'device_activity.png'")
        plt.show()
    except ImportError:
        print("⚠️ matplotlib not installed - skipping plots")


if __name__ == "__main__":
    main()