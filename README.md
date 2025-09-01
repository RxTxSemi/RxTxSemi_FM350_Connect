# RxTxSemi FM350-GL Connect (Linux)

A Linux GUI tool for monitoring and managing Fibocom FM350-GL modems.

👉 Don’t have the modem yet? Get the official RxTxSemi FM350-GL 5G USB Dongle here:  
🔗 Buy from [ElectroMela](https://electromela.in)  

---

## ✨ Features
- Serial port selection and monitoring  
- APN configuration  
- Real-time connection and signal status  
- Data usage and speed monitoring  
- GUI built with Tkinter  

---

## 🛠️ Supported Kernel Versions
- Native support for the Fibocom FM350-GL is included starting from **Linux kernel 6.11-rc1** (patch merged on 2024-06-27).  
- On kernel **6.11-rc1 or newer**, no manual patching is required.  
- On **older kernels**, you may need to patch or build a custom kernel.  

---

## 🚀 Quick Start
You don’t need to install Python or dependencies.  
Just download the prebuilt GUI app from the [Releases page](https://github.com/RxTxSemi/RxTxSemi_FM350Linux/releases), make it executable, and run:

```bash
wget https://github.com/RxTxSemi/RxTxSemi_FM350Linux/releases/latest/download/rxtxsemi-fm350
chmod +x rxtxsemi-fm350
./rxtxsemi-fm350
```

---

## 🔑 Grant Modem Access
Modem serial ports (`/dev/ttyUSB*`) are owned by the **dialout** group.  
Add your user to the group:

```bash
sudo usermod -a -G dialout $USER
newgrp dialout
```

You may need to **log out and log back in** for changes to take effect.  

---
