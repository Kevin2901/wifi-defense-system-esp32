#include <WiFi.h>
#include <HTTPClient.h>
#include <esp_wifi.h>

const char* ssid = "Kevin;
const char* password = "kevin";
const char* serverName = "http://192.168.1.7:5000/data";

// Packet data
volatile bool packetReceived = false;
String srcIP = "";
String destIP = "";
uint16_t srcPort = 0;
uint16_t destPort = 0;
uint8_t protocol = 0;
size_t packetSize = 0;

// Sniffer callback
void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_DATA) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
        uint8_t *data = pkt->payload;
        int length = pkt->rx_ctrl.sig_len;

        // Check for IP packets
        if (length >= 34) {
            int ipHeaderStart = 42; // Adjusted to skip the radiotap header

            // Extract IP addresses
            srcIP = String(data[ipHeaderStart + 12]) + "." +
                    String(data[ipHeaderStart + 13]) + "." +
                    String(data[ipHeaderStart + 14]) + "." +
                    String(data[ipHeaderStart + 15]);

            destIP = String(data[ipHeaderStart + 16]) + "." +
                     String(data[ipHeaderStart + 17]) + "." +
                     String(data[ipHeaderStart + 18]) + "." +
                     String(data[ipHeaderStart + 19]);

            // Check if the packet is not from or to this device
            if (srcIP != WiFi.localIP().toString() && destIP != WiFi.localIP().toString()) {
                // Extract protocol (TCP = 6, UDP = 17)
                protocol = data[ipHeaderStart + 9];

                // Extract ports (if TCP or UDP)
                if (protocol == 6 || protocol == 17) {
                    srcPort = (data[ipHeaderStart + 20] << 8) | data[ipHeaderStart + 21];
                    destPort = (data[ipHeaderStart + 22] << 8) | data[ipHeaderStart + 23];
                }

                packetSize = length;
                packetReceived = true;
            }
        }
    }
}

void setup() {
    Serial.begin(115200);

    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    Serial.println("Connecting to WiFi...");
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting...");
    }

    Serial.println("Connected to WiFi");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());

    // Set up promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
}

void loop() {
    if (packetReceived) {
        if ((WiFi.status() == WL_CONNECTED)) {
            HTTPClient http;
            http.begin(serverName);
            http.addHeader("Content-Type", "application/json");

            String jsonData = "{\"source_ip\":\"" + srcIP + 
                               "\", \"destination_ip\":\"" + destIP + 
                               "\", \"source_port\":" + String(srcPort) +
                               ", \"destination_port\":" + String(destPort) +
                               ", \"protocol\":" + String(protocol) +
                               ", \"packet_size\":" + String(packetSize) + "}";
                               
            int httpResponseCode = http.POST(jsonData);

            if (httpResponseCode > 0) {
                String response = http.getString();
                Serial.println("HTTP Response Code: " + String(httpResponseCode));
                Serial.println("Response: " + response);
            } else {
                Serial.println("Error on HTTP request");
            }
            http.end();
        }

        packetReceived = false; // Reset the flag
    }

    delay(10); // Short delay to capture more packets
}