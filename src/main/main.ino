/* -------------------------------------------------------------
   Wi-Fi Defense Dashboard – ESP-WROOM-32 web server
   Upgrades:
     - deauth detection (promiscuous monitor)
     - MAC randomization detection (locally-administered MAC)
     - hotspot takeover detection (duplicate SSIDs / large RSSI changes)
   ------------------------------------------------------------- */

#include <WiFi.h>
#include <WebServer.h>
#include <FS.h>
#include <SPIFFS.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"    // for promiscuous API

// Add the missing STL headers
#include <map>
#include <vector>
#include <algorithm>   // for std::min

// ---------- Settings ----------
const char* ssidAP      = "NAME";   // hotspot name
const char* passwordAP  = "PASSWORD";      // hotspot password

WebServer server(80);                     // tiny HTTP server on port 80

String    jsonPayload = "{}";             // holds the latest scan result
unsigned long lastScan = 0;
const unsigned long scanInterval = 5000;  // 5 seconds between scans

// ---------- History for takeover detection ----------
struct NetInfo {
  String ssid;
  String bssid;
  int rssi;
  int channel;
  String encryption;
};

#define MAX_HISTORY 128
NetInfo prevScan[MAX_HISTORY];
int prevCount = 0;

// ---------- Deauth detection ----------
#define DEAUTH_WINDOW_MS 10000    // time window to evaluate deauth hits
#define DEAUTH_THRESHOLD 5        // threshold in window to trigger warning
static std::vector<unsigned long> deauthTimestamps; // when deauth frames seen

// promiscuous callback
void wifiPromiscCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  // only handle raw packets
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*) buf;
  if (!pkt) return;
  const uint8_t *payload = pkt->payload; // raw 802.11 frame
  if (!payload) return;
  uint8_t fc0 = payload[0];
  uint8_t subtype = fc0 >> 4;
  uint8_t typeBits = (fc0 >> 2) & 0x03;
  // Management frame has typeBits == 0
  // Deauthentication frames have subtype == 0x0C (12 decimal)
  if (typeBits == 0 && subtype == 0x0C) {
    unsigned long now = millis();
    deauthTimestamps.push_back(now);
    // prune old timestamps
    while (!deauthTimestamps.empty() && now - deauthTimestamps.front() > DEAUTH_WINDOW_MS) {
      deauthTimestamps.erase(deauthTimestamps.begin());
    }
  }
}

// ---------- Helpers ----------
bool isLocallyAdministeredMac(const String &bssid) {
  // bssid format: "aa:bb:cc:dd:ee:ff"
  if (bssid.length() < 2) return false;
  String firstOct = bssid.substring(0, 2);
  char buf[3];
  firstOct.toCharArray(buf, 3);
  int val = (int) strtol(buf, nullptr, 16);
  return (val & 0x02) != 0;
}

// simple vendor guess of OUI (small map)
String vendorFromBssid(const String &bssid) {
  if (bssid.length() < 8) return "Unknown";
  String key = bssid.substring(0, 8);
  key.toUpperCase();
  if (key == "24:5E:BE") return "TP-Link";
  if (key == "F0:9F:C2") return "Netgear";
  if (key == "A4:2B:B0") return "Xiaomi";
  if (key == "C0:3F:D5") return "Cisco";
  if (key == "28:6C:07") return "Apple";
  if (key == "70:EE:50") return "Samsung";
  return "Unknown";
}

// find previous network by SSID or BSSID
int findPrevByBssid(const String &bssid) {
  for (int i = 0; i < prevCount; ++i) {
    if (prevScan[i].bssid == bssid) return i;
  }
  return -1;
}
int findPrevBySsid(const String &ssid) {
  for (int i = 0; i < prevCount; ++i) {
    if (prevScan[i].ssid == ssid) return i;
  }
  return -1;
}

/* -------------------------------------------------------------
   Convert scan results into a JSON string (now with warnings)
   ------------------------------------------------------------- */
String buildJsonFromScan() {
  int n = WiFi.scanComplete();                 // -1 = still scanning
  if (n == -1) return jsonPayload;            // keep old data

  DynamicJsonDocument doc(8192); // increased to hold warnings/history
  JsonArray networks = doc.createNestedArray("networks");
  JsonArray warnings = doc.createNestedArray("warnings");

  // local containers for detection
  // map SSID -> vector of indices in this scan
  std::map<String, std::vector<int>> ssidMap;

  // read current scan into a local list
  std::vector<NetInfo> cur;
  cur.reserve(n > 0 ? n : 0);
  for (int i = 0; i < n; ++i) {
    NetInfo info;
    info.ssid = WiFi.SSID(i);
    info.bssid = WiFi.BSSIDstr(i);
    info.rssi = WiFi.RSSI(i);
    info.channel = WiFi.channel(i);
    info.encryption = WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "WPA/WPA2";
    cur.push_back(info);
    ssidMap[info.ssid].push_back(i);
  }

  // populate networks array and compute per-network flags
  for (int i = 0; i < n; ++i) {
    NetInfo &info = cur[i];
    JsonObject net = networks.createNestedObject();
    net["ssid"]       = info.ssid;
    net["bssid"]      = info.bssid;
    net["rssi"]       = info.rssi;
    net["channel"]    = info.channel;
    net["encryption"] = info.encryption;
    net["vendor"]     = vendorFromBssid(info.bssid);
    net["is_random_mac"] = isLocallyAdministeredMac(info.bssid);

    // check if this SSID has multiple BSSIDs in this scan -> suspicious
    bool multiBssid = ssidMap[info.ssid].size() > 1;
    net["multi_bssid"] = multiBssid;

    // suspect takeover detection: compare with previous scan
    bool suspect_takeover = false;
    int prevIdx = findPrevBySsid(info.ssid);
    if (prevIdx >= 0) {
      int prevRssi = prevScan[prevIdx].rssi;
      if ((info.rssi - prevRssi) >= 30) { // 30 dB jump
        suspect_takeover = true;
      }
      if (prevScan[prevIdx].bssid != info.bssid) {
        if (prevScan[prevIdx].encryption != info.encryption) {
          suspect_takeover = true;
        }
      }
    }
    net["suspect_takeover"] = suspect_takeover;
  }

  // Cross-SSID analysis: duplicate SSIDs
  for (auto &entry : ssidMap) {
    const String ss = entry.first;
    if (ss.length() == 0) continue; // skip hidden
    if (entry.second.size() > 1) {
      String msg = "Duplicate SSID seen: " + ss + " (" + String(entry.second.size()) + " BSSIDs)";
      warnings.add(msg);
    }
  }

  // Deauth analysis: how many deauth frames in recent window?
  unsigned long now = millis();
  // prune deauth timestamps older than window
  while (!deauthTimestamps.empty() && now - deauthTimestamps.front() > DEAUTH_WINDOW_MS) {
    deauthTimestamps.erase(deauthTimestamps.begin());
  }
  int deauthCount = (int)deauthTimestamps.size();
  if (deauthCount >= DEAUTH_THRESHOLD) {
    String msg = "High number of deauthentication frames detected: " + String(deauthCount);
    warnings.add(msg);
  } else if (deauthCount > 0) {
    String msg = "Deauthentication frames detected: " + String(deauthCount);
    warnings.add(msg);
  }

  // If any suspect_takeover true, add warnings
  for (int i = 0; i < n; ++i) {
    JsonObject net = networks[i];
    if (net["suspect_takeover"] == true) {
      String s = "Possible takeover for SSID: " + String((const char*)net["ssid"]) + " (BSSID " + String((const char*)net["bssid"]) + ")";
      warnings.add(s);
    }
    if (net["is_random_mac"] == true) {
      String s = "MAC appears locally administered (randomized): " + String((const char*)net["bssid"]);
      warnings.add(s);
    }
  }

  // attach meta info
  doc["timestamp"] = now;
  doc["warnings_count"] = warnings.size();

  // Save current scan into prevScan (for next round)
  prevCount = 0;
  int store = std::min(n, MAX_HISTORY);
  for (int i = 0; i < store; ++i) {
    prevScan[i] = cur[i];
    prevCount++;
  }

  WiFi.scanDelete();               // free memory for the next round
  String out;
  serializeJson(doc, out);
  return out;
}

/* -------------------------------------------------------------
   HTTP handlers – what the ESP sends back
   ------------------------------------------------------------- */
void handleRoot() {
  File file = SPIFFS.open("/index.html", "r");
  if (!file) { server.send(404, "text/plain", "File not found"); return; }
  server.streamFile(file, "text/html");
  file.close();
}

void handleScan() {
  server.sendHeader("Cache-Control", "no-cache");
  server.send(200, "application/json", jsonPayload);
}

/* -------------------------------------------------------------
   Setup – runs once when the ESP starts
   ------------------------------------------------------------- */
void setup() {
  Serial.begin(115200);
  // start the little file system that holds our web page
  if (!SPIFFS.begin(true)) {
    Serial.println("❌ Failed to mount SPIFFS");
    return;
  }

  // create a Wi-Fi hotspot (AP) that we can connect to
  WiFi.softAP(ssidAP, passwordAP);
  IPAddress ip = WiFi.softAPIP();
  Serial.print("✅ AP IP address: ");
  Serial.println(ip);

  // register the two pages we will serve
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.begin();

  // start the first asynchronous Wi-Fi scan
  WiFi.scanNetworks(true, true);   // async, include hidden networks

  // start promiscuous mode to detect management frames (deauth)
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiPromiscCb);
  // Note: promiscuous may affect WiFi performance; we leave it enabled for monitoring
}

/* -------------------------------------------------------------
   Loop – runs over and over again
   ------------------------------------------------------------- */
void loop() {
  server.handleClient();           // answer any web requests

  // every few seconds start a new scan and store the result
  if (millis() - lastScan > scanInterval) {
    int scanResult = WiFi.scanComplete();   // did the previous scan finish?
    if (scanResult != -1) {                  // -1 means still busy
      jsonPayload = buildJsonFromScan();     // keep fresh data
      WiFi.scanDelete();                     // clean up
      WiFi.scanNetworks(true, true);         // start next async scan
      lastScan = millis();
      // debug print summary
      Serial.println(jsonPayload);
    }
  }
}
