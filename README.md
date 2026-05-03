# MAX77705 Power Management Register Parser

**max77705parser.py** is a Python 3 command-line tool for parsing and decoding register dumps from Samsung MAX77705-based power management systems. It reads CSV-formatted register snapshots from devices such as smartphones or tablets, and outputs a clear, human-readable summary of the charger, fuel gauge, MUIC (USB-C), and PMIC subsystems.

## Features

- **Decodes raw register values** for MAX77705 and related power management ICs.
- **Interprets and labels registers** for charger, fuel gauge, MUIC (USB-C), and PMIC sections.
- **Highlights abnormal readings** and unknown registers for easier troubleshooting.
- **Outputs a formatted summary** for quick diagnostics and log sharing.

## Example Output
```
-------------------- Fuel Gauge --------------------
Register   | Name                 | Raw      | Decoded
--------------------------------------------------
0x0        | STATUS_REG           | 0x8000   | Status: POR=0, Imn=0, Imx=0, Vmn=0, Vmx=0, Tmn=0, Tmx=0
0x2        | VCELL_REG            | 0x807f   | Cell Voltage: 2569.92 mV
0x4        | SOC_STATUS           | 0x19     | SOC = 0.0%  Flags: DataReady
0x5        | REMCAP_REP_REG       | 0xdf10   | Reported Remaining Capacity: 28552.0 mAh  ⚠️ capacity 28552 mAh exceeds typical range
0x6        | SOCREP_REG           | 0x2460   | Reported SOC: 36.4%
0x8        | VERSION_REG          | 0xcd1d   | Version: 0xCD1D
0xa        | HIBRT_REG            | 0xa600   | HibRt: 0xA600
0xc        | CONFIG_REG           | 0x400    | Sleep=4, Alert=0% (Voltage change)
0xd        | SOCMIX_REG           | 0x7e5f   | Mixed SOC: 100.0%
0xe        | SOCAV_REG            | 0x3460   | Average SOC: 52.4%
0xf        | REMCAP_MIX_REG       | 0xe110   | Mixed Remaining Capacity: 28808.0 mAh
0x10       | FULLCAP_REG          | 0x8911   | Full Capacity: 17544.5 mAh  ⚠️ capacity 17544 mAh exceeds typical range
```
## Use Cases
```
- **Battery and charging diagnostics** for embedded developers and repair technicians.
- **Automated test logs** for hardware validation.
- **Reverse engineering** of power management behavior in consumer electronics.

## Usage
```
python3 max77705parser.py <register_dump.csv>
```


## Requirements

- Python 3.x

## Contributing

Pull requests and issue reports are welcome! Please include sample register dumps if reporting parsing errors.

---

*For more details, see the code comments and the [MAX77705 datasheet](https://www.maximintegrated.com/en/products/power/battery-management/MAX77705.html) for register definitions.*
