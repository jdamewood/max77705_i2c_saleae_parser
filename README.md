# MAX77705 Power Management Register Parser

**max77705parser.py** is a Python 3 command-line tool for parsing and decoding register dumps from Samsung MAX77705-based power management systems. It reads CSV-formatted register snapshots from devices such as smartphones or tablets, and outputs a clear, human-readable summary of the charger, fuel gauge, MUIC (USB-C), and PMIC subsystems.

## Features

- **Decodes raw register values** for MAX77705 and related power management ICs.
- **Interprets and labels registers** for charger, fuel gauge, MUIC (USB-C), and PMIC sections.
- **Highlights abnormal readings** and unknown registers for easier troubleshooting.
- **Outputs a formatted summary** for quick diagnostics and log sharing.

## Example Output
```
-------------------- Charger --------------------
Register | Name | Raw | Decoded
0xb7 | CNFG_00 | 0x15 | Charger Config 00: 0x15
...
-------------------- Fuel Gauge --------------------
Register | Name | Raw | Decoded
0x8 | TEMPERATURE_REG | 0xcd1d | Temperature: 205.11°C

## Use Cases
```
- **Battery and charging diagnostics** for embedded developers and repair technicians.
- **Automated test logs** for hardware validation.
- **Reverse engineering** of power management behavior in consumer electronics.

## Usage ```
python3 max77705parser.py <register_dump.csv>```


## Requirements

- Python 3.x

## Contributing

Pull requests and issue reports are welcome! Please include sample register dumps if reporting parsing errors.

---

*For more details, see the code comments and the [MAX77705 datasheet](https://www.maximintegrated.com/en/products/power/battery-management/MAX77705.html) for register definitions.*
