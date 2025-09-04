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

## ⚙️ Configure udev Rules

In some cases, **ModemManager may interfere** with the FM350-GL modem.  
You can add a udev rule to prevent ModemManager from claiming the device.

### Step 1: Create the rule file
Open a new udev rules file:

```bash
sudo nano /etc/udev/rules.d/99-fm350.rules
```

### Step 2: Add the rule
Paste the following line inside the file:

```text
ATTRS{idVendor}=="0e8d", ATTRS{idProduct}=="7127", ENV{ID_MM_DEVICE_IGNORE}="1"
```

### Step 3: Reload and apply rules
Run the following commands:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Step 4: Restart ModemManager
```bash
sudo systemctl restart ModemManager
```

---

