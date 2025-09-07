# 🔧 Setup Guide for ESP32 Wi-Fi Defense System

This guide explains how to set up, compile, and run the project.

---

## 1. Requirements
- ESP32 development board
- USB cable
- Arduino IDE or PlatformIO
- GitHub Desktop (for project updates)

---

## 2. Clone Repository
1. Open GitHub Desktop
2. Clone the repository `wifi-defense-system-esp32`
3. Open the project folder

---

## 3. Arduino IDE Setup
1. Install **Arduino IDE** (https://www.arduino.cc/en/software)
2. Add ESP32 Board:
   - File → Preferences → Paste this in “Additional Boards Manager URLs”:
     ```
     https://dl.espressif.com/dl/package_esp32_index.json
     ```
   - Then go to Tools → Board → Boards Manager → Install "ESP32 by Espressif Systems"
3. Select your ESP32 board (e.g., ESP32 Dev Module)

---

## 4. Upload Code
1. Open `src/main.ino` in Arduino IDE
2. Connect ESP32 via USB
3. Select correct COM port under Tools → Port
4. Click **Upload**

---

## 5. Monitor Logs
- Open Arduino Serial Monitor
- Baud rate: **115200**
- You will see alerts for detected **de-auth packets** and **anomalies**

---

✅ Done! Your ESP32 Wi-Fi defense system is running.
