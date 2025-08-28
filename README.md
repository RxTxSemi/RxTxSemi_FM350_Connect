# RxTxSemi FM350-GL Connect (Linux)

A Linux GUI tool for monitoring and managing Fibocom FM350-GL modems. This application replicates the functionality of the Windows Fibocom Connect FM350 tool, providing a native graphical interface for serial port management, APN configuration, and real-time modem status.

## Features
- Serial port selection and monitoring
- APN configuration
- Real-time connection and signal status
- Data usage and speed monitoring (requires `psutil`)
- GUI built with Tkinter

## Requirements
- Python 3.7+
- The following Python packages (install with pip):
  - pyserial
  - Pillow
  - psutil (optional, for data usage graphs)

## Supported Kernel Versions
- Native support for the Fibocom FM350-GL in the Linux kernel’s `option` driver is included starting from **Linux kernel 6.11-rc1** (patch: "USB: serial: option: add Fibocom FM350-GL", merged on 2024-06-27).
- If you are using **kernel 6.11-rc1 or newer**, no manual patching is required.
- For older kernels, you must apply the patch manually or use a custom kernel build.
- You can check the [kernel.org changelogs](https://kernel.org/) or the [option.c driver history](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/drivers/usb/serial/option.c) for more details.

## Installation
1. Install Python 3 if not already installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the application with:
```bash
python3 RxTxSemi_FM350Linux.py
```

## Optional Assets
- Place `rxtxsemi_logo.png` and `bmc_qr.png` in the same directory as the script for branding and donation features. The app will work without them, but some UI elements will show fallback text.

## Notes
- The application may require root privileges for certain network operations. It uses `pkexec` for privilege escalation.
- Make sure your user has permission to access serial ports (e.g., add to the `dialout` group on Linux).

## License
Designed with love by Vamsi. See the script for more details. 