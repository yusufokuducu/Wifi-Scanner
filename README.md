# Network Scanner App

Bu proje, yerel ağınızdaki cihazları taramak için basit bir GUI uygulamasıdır. Uygulama, IP aralığını belirterek ağınızdaki cihazların IP adreslerini, MAC adreslerini ve cihaz adlarını bulmanıza yardımcı olur.

## Özellikler

- **Ağ Tarama**: Belirtilen IP aralığında cihazları tarar.
- **Sonuçları Görüntüleme**: Tarama sonuçlarını kullanıcı arayüzünde görüntüler.
- **Sonuçları Temizleme**: Önceki tarama sonuçlarını temizleme imkanı.
- **Sonuçları CSV Olarak Kaydetme**: Tarama sonuçlarını CSV formatında kaydetme.
- **Tarama Geçmişi**: Önceki tarama sonuçlarını saklama.

## Gereksinimler

Bu uygulama, aşağıdaki Python kütüphanelerine ihtiyaç duyar:

- `tkinter`
- `customtkinter`
- `scapy`
- `socket`
- `csv`

## Kurulum

1. Projeyi klonlayın veya indirin:
   ```bash
   git clone <repository-url>
   cd test2
   ```

2. Gerekli kütüphaneleri yükleyin:
   ```bash
   pip install customtkinter scapy
   ```

3. Uygulamayı çalıştırın:
   ```bash
   python test2.py
   ```

## Kullanım

1. Uygulama açıldığında, taramak istediğiniz IP aralığını girin (örneğin: `192.168.1.1/24`).
2. "Ağı Tara" butonuna tıklayarak tarama işlemini başlatın.
3. Tarama sonuçları, uygulama penceresinde görüntülenecektir.
4. Sonuçları CSV formatında kaydetmek için "Sonuçları CSV Olarak Kaydet" butonuna tıklayın.
5. Önceki sonuçları temizlemek için "Sonuçları Temizle" butonuna tıklayın.

## Katkıda Bulunma

Bu projeye katkıda bulunmak isterseniz, lütfen bir pull request oluşturun veya önerilerinizi paylaşın.

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakın.