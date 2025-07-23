#include <ESP8266WiFi.h>
#include <set>
#include <string>
#include <map>

std::map<std::string, std::string> deviceToBssid;
std::set<std::string> uniqueMacs;
std::set<std::string> uniqueBssid;

volatile int packets = 0;
volatile int tmpDeauths = 0;
unsigned long channelAuto = millis();
bool sniifer = true;

// Access Point'leri tarayıp BSSID'leri kaydeder
void AccesPointScan() {
  int n = WiFi.scanNetworks(false, true);

  if (n <= 0) {
    Serial.println("Hiç Access Point yok");
  } else {
    for (int i = 0; i < n; i++) {
      uint8_t* bssid = WiFi.BSSID(i);
      char bssidStr[18];
      snprintf(bssidStr, sizeof(bssidStr),
               "%02X:%02X:%02X:%02X:%02X:%02X",
               bssid[0], bssid[1], bssid[2],
               bssid[3], bssid[4], bssid[5]);
      uniqueBssid.insert(std::string(bssidStr));
    }
  }
}

// Broadcast MAC adreslerini filtreler (FF:FF:FF:FF:FF:FF)
bool macBrodcast(uint8_t* mac) {
  for (int i = 0; i < 6; i++)
    if (mac[i] != 0xFF) return false;
  return true;
}

// Yerel, rastgele oluşturulmuş MAC adreslerini tespit eder
bool isRandomMac(uint8_t* mac) {
  return (mac[0] & 0x02); // İlk bayttaki LSB'den ikinci bit: 1 ise local (sahte) MAC
}

// Multicast adres olup olmadığını kontrol eder
bool MacMultiCast(uint8_t* mac) {
  return (mac[0] & 0x01) == 0x01; // LSB: 1 ise multicast, 0 ise unicast
}

// Geçersiz (00:00:00:00:00:00 gibi) MAC adreslerini kontrol eder
bool macValid(uint8_t* mac) {
  for (int i = 0; i < 6; i++)
    if (mac[i] != 0x00) return true;
  return false;
}

extern "C" {
  void sniffer(uint8_t* buf, uint16_t len) {
    if (len < 28) return; // Çok kısa paketler analiz edilmez
    uint8_t * bssidMac = &buf[28]; // bssid alanı 
    uint8_t frameType = buf[12]; // Frame Control alanı

    // Data frame değilse çık
    if ((frameType & 0x0C) != 0x08) return;

    // Deauth/Disassociation tespit edilirse sayaç artırılır ve çıkılır
    if (frameType == 0xC0 || frameType == 0xA0) {
      tmpDeauths++;
      return;
    }

    // Beacon, Probe Request/Response gibi yönetim çerçeveleri filtrelenir
    if (frameType == 0x80 || frameType == 0x40 || frameType == 0x50) {
      return;
    }

    uint8_t* macTo = &buf[16];   // Hedef MAC
    uint8_t* macFrom = &buf[22]; // Kaynak MAC

    // Broadcast, multicast, geçersiz veya rastgele MAC adresleri filtrelenir
    if (macBrodcast(macTo) || macBrodcast(macFrom) ||
        !macValid(macTo) || !macValid(macFrom) ||
        MacMultiCast(macTo) || MacMultiCast(macFrom) ||
        isRandomMac(macTo) || isRandomMac(macFrom))
      return;
    
    char macToStr[18],macFromStr[18],bssidStr[18];
    // Geçerli MAC adresleri string formatına çevrilip kaydedilir
    snprintf(macToStr, sizeof(macToStr),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             macTo[0], macTo[1], macTo[2],
             macTo[3], macTo[4], macTo[5]);
    uniqueMacs.insert(std::string(macToStr));

    snprintf(macFromStr, sizeof(macFromStr),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             macFrom[0], macFrom[1], macFrom[2],
             macFrom[3], macFrom[4], macFrom[5]);
    uniqueMacs.insert(std::string(macFromStr));

    snprintf(bssidStr,sizeof(bssidStr),"%02X:%02X:%02X:%02X:%02X:%02X",
            bssidMac[0],bssidMac[1],bssidMac[2],bssidMac[3],bssidMac[4],bssidMac[5]);
    

    std::string fromstr(macFromStr);
    std::string toStr(macToStr); 
    std::string bssidString(bssidStr); 

    if(memcmp(macTo,bssidMac,6) == 0 && memcmp(macFrom,bssidMac,6) !=0) { 
      deviceToBssid[fromstr] = bssidString; 
    } else if(memcmp(macFrom,bssidMac,6) == 0 && memcmp(macTo,bssidMac,6) !=0) { 
      deviceToBssid[toStr] = bssidString;
    }
    packets++;
  }
}

void setup() {
  channelAuto = millis();
  Serial.begin(115200);
  WiFi.mode(WIFI_STA); 
  WiFi.disconnect();
  delay(100);
}

void loop() {
  static unsigned long lastChannelChange = 0;
  static unsigned long lastPrint = 0;
  static unsigned long lastSniifer = 0;
  static unsigned long lastAPScan = 0;
  unsigned long now = millis();

  // 1–16 saniyede paket toplama başlar
  if (now - lastSniifer >= 1000 && now - lastSniifer < 16000) {
    wifi_promiscuous_enable(1);
    wifi_set_promiscuous_rx_cb(&sniffer);
    sniifer = true;
  }
  // 16. saniyede durur
  else if (now - lastSniifer >= 16000) {
    wifi_promiscuous_enable(0);
    sniifer = false;
  }

  // 17–32 saniyede Access Point taraması yapılır
  if (now - lastSniifer >= 17000 && now - lastSniifer < 32000) {
    if (now - lastAPScan >= 15000) {
      AccesPointScan();
      lastAPScan = now;
    }
  }

  // 31. saniyede sayaçlar sıfırlanır
  if (now - lastSniifer >= 31000) {
    lastSniifer = now;
    lastAPScan = now;
  }

  // Her 200 ms’de kanal değiştir
  if (now - lastChannelChange > 200) {
    static int channel = 1;
    wifi_set_channel(channel);
    channel = (channel % 13) + 1;
    lastChannelChange = now;
  }

  // Her 60 saniyede bir sonuç yazdırılır
  if (now - lastPrint > 60000) {
    Serial.println("\n--- MAC Adresleri ---");
    for (const auto& mac : uniqueMacs) {
      bool found = false;
      for (const auto& bssid : uniqueBssid) {
        if (mac == bssid) {
          found = true;
          break;
        }
      }
      if (!found) {
        Serial.printf("MAC: %s\n", mac.c_str());
      }
    }
    Serial.println("----Bssid lsitesi---- ");
    for (const auto& bssid: uniqueBssid) {
      Serial.printf("Bssid: %s\n" ,bssid.c_str());
    }

    Serial.println("\n--- Cihaz - BSSID Eşleşmeleri ---");
    for (const auto& pair : deviceToBssid) {
      Serial.printf("Cihaz: %s -> BSSID: %s\n", pair.first.c_str(), pair.second.c_str());
}


    lastPrint = now;
  }
}
