# MAX77705 / MAX77804 I2C Protocol Analyzer

Tools to decode and analyze I2C traffic from Maxim MAX77705/MAX77804 Power Management ICs, including fuel gauge, MUIC (USB‑C), charger, PMIC, and RGB LED controller.

## Overview

This repository contains two main scripts:

- **`max77804saleaeMCP.py`** – Connects to Saleae Logic 2 via MCP (Model Context Protocol), loads a `.sal` capture, exports I2C transactions, and decodes them in real‑time with color‑coded output.  
- **`max77705parser.py`** – Parses a Saleae‑exported CSV file (e.g., `batt‑power‑on.csv`) and produces a detailed register‑by‑register decoded summary.

Both scripts support:
- Fuel Gauge (MAX17050) – voltage, current, temperature, SOC, capacity, cycle count, etc.
- PMIC (MAX77705) – charger interrupts, flash/torch control, input current limit, etc.
- MUIC (USB‑C controller) – CC status, VBUS detection, PD interrupts, accessory detection.
- RGB LED controller – LED enable, brightness, blink patterns (address 0x48).

## Files

| File | Description |
|------|-------------|
| `max77804saleaeMCP.py` | Live I2C decoder using Saleae MCP server |
| `max77705parser.py` | Post‑processing of Saleae CSV export |
| `batt‑power‑on.csv` | Example I2C capture (Saleae CSV format) |
| `README.md` | This file |

## Requirements

- Python 3.7+
- Saleae Logic 2 (for the MCP script)
- Python packages:
  ```bash
  pip install requests pandas matplotlib colorama
```
## Usage
1 Real‑time decoding with Saleae MCP
- Open Saleae Logic 2, start the MCP server (Extensions → MCP Server).
- Edit the script variables:
-- CAPTURE_FILE – path to your .sal file.
-- BUSES – define SDA/SCL channel numbers for each I2C bus.

*For more details, see the code comments and the [MAX77705 datasheet](https://www.maximintegrated.com/en/products/power/battery-management/MAX77705.html) for register definitions.*


# MAX77804 Power Management Register Parser using Saleae MCP remote features to read .sal files into i2c parsed data.
