# Görev Yöneticisi: Tasarım

Tarih: 2026-11-26

## Amaç ve neden

Kullanıcı Windows 11 için kendi görev yöneticisini istiyor. İki sebebi var:

1. **Gizlenen virüsler:** Bazı zararlı programlar Windows Görev Yöneticisi'nde görünmüyor.
2. **Daha fazla veri ve daha modern bir tasarım:** CPU, GPU, RAM, disk ve ağ kullanımı program bazında, tek ekranda görünsün.

Kullanıcı soruları geçip kararları geliştiriciye bıraktı ("2. yol"). Ayrıca her geliştirme adımında iki ayrı inceleyici ajanla tartışılmasını ve düzeltmelerin uygulanmasını istedi.

## Hedefler

- CPU, GPU, RAM, disk ve ağın canlı toplam kullanımı ve grafikleri.
- Program bazında CPU %, RAM, GPU %, GPU belleği ve disk G/Ç.
- Gizli işlem tespiti (çapraz kontrol): işlem listesini birden fazla bağımsız yöntemle alıp farkları göstermek.
- Şüpheli işaretleme: imzasız dosyalar, geçici/kullanıcı klasörlerinden çalışan programlar, sistem dosyası adını taklit eden programlar.
- Ağ bağlantıları: hangi programın nereye bağlı olduğu.
- Başlangıç öğeleri: Run anahtarları, Başlangıç klasörleri, zamanlanmış görevler, servisler, Winlogon ve IFEO.
- İşlem eylemleri: sonlandır, dosya konumunu aç, VirusTotal'de SHA-256 ile ara (dosya yüklenmez, yalnızca karma ile tarayıcıda arama açılır).
- Modern, koyu/açık tema destekli Fluent görünüm. Arayüz dili Türkçe.

## Hedef olmayanlar

- Çekirdek sürücüsü yazmak. Gerçek çekirdek seviyesi rootkit tespiti bu projenin kapsamı dışında. Uygulama bu sınırı arayüzde dürüstçe söyler.
- Antivirüs gibi imza veritabanı ile tarama yapmak.
- Linux veya macOS desteği.

## Anti-hedefler (çalışsa bile başarısızlık sayılacak durumlar)

- Her Windows dosyasını "imzasız" diye işaretleyip kullanıcıyı korkutmak. Katalog imzası mutlaka kontrol edilmeli.
- Kullanıcıya "virüs yok" diyerek sahte güven vermek.
- Bilgisayarı yavaşlatmak. Varsayılan yenileme 1 saniye; ağır taramalar (imza, karma, başlangıç) arka planda ve önbellekli yapılır.
- Kullanıcının dosyalarını bir yere yüklemek.

## Kısıtlar

- Geliştirme Linux bulut makinesinde yapılıyor, uygulama Windows 11'de çalışacak. Windows'a özgü kod burada derlenebilir ama çalıştırılamaz.
  - **Doğrulama:** Platformdan bağımsız mantık Linux'ta birim testleriyle doğrulanır. Derleme, testler ve tek dosyalık `.exe` yayını GitHub Actions'da `windows-latest` üzerinde yapılır.
- Kullanıcının elinde indirip çift tıklayacağı tek bir `.exe` olmalı. Ayrıca .NET kurmak gerekmemeli (self-contained).
- Tüm işlemleri görebilmek için yönetici izni gerekir. Uygulama manifest ile yönetici olarak açılır.

## Değerlendirilen yaklaşımlar

| Yaklaşım | Artı | Eksi |
|---|---|---|
| **C# .NET 8 + WPF (WPF-UI ile Fluent görünüm)**, seçilen | Windows API'lerine (NtQuerySystemInformation, PDH, WinVerifyTrust, IP Helper) doğrudan P/Invoke ile erişim; tek dosya self-contained exe; Linux'ta derlenebiliyor (EnableWindowsTargeting) | Arayüz Linux'ta çalıştırılıp görülemez |
| Python + psutil + PySide6 | Hızlı yazılır | GPU başına işlem, imza kontrolü ve çapraz kontrol için yine ctypes gerekir; exe büyük ve antivirüslerce sık yanlış alarm alır |
| Electron / Tauri + web arayüzü | Çok modern görünüm kolay | Ağır (Electron) ya da native kısım için yine Rust/C# gerekir; iki katman |

C# seçildi, çünkü gizli işlem tespiti ve imza kontrolü düşük seviye Windows API'si istiyor ve C# bunlara en temiz erişimi veriyor.

## Mimari

```
src/
  GorevYoneticisi.Core/      net8.0, platformdan bağımsız mantık (Linux'ta test edilir)
    Modeller, çapraz kontrol analizi, şüphe puanlama, GPU sayaç adı ayrıştırma,
    oran hesapları (CPU %, MB/s), biçimlendirme, geçmiş halka tamponu
  GorevYoneticisi.App/       net8.0-windows, WPF arayüz + Windows veri toplayıcıları
    Native/                  P/Invoke tanımları
    Collectors/              CPU/RAM/GPU/disk/ağ/işlem/başlangıç/imza toplayıcıları
    ViewModels/, Views/      MVVM (CommunityToolkit.Mvvm)
tests/
  GorevYoneticisi.Core.Tests/  xUnit
.github/workflows/build.yml    Windows'ta derleme, test, exe yayını, "latest" sürümü
```

### Veri kaynakları

- **İşlemler (ana kaynak):** `NtQuerySystemInformation(SystemProcessInformation)`. Her işlemin CPU zamanı, bellek, iş parçacığı ve G/Ç sayaçları tek çağrıda, işlemi açmadan gelir.
- **Toplam CPU:** `GetSystemTimes` farkları.
- **Toplam RAM:** `GlobalMemoryStatusEx`.
- **GPU:** PDH `GPU Engine(*)\Utilization Percentage` ve `GPU Process Memory(*)\Dedicated Usage`. Örnek adlarındaki `pid_1234` ile işleme eşlenir. Bu, Windows Görev Yöneticisi'nin kullandığı yöntemin aynısı.
- **Disk:** İşlem başına G/Ç farkları (okuma+yazma bayt/sn). Toplam için PDH `PhysicalDisk(_Total)`.
- **Ağ:** Toplam için `NetworkInterface` istatistikleri. Bağlantılar için `GetExtendedTcpTable` / `GetExtendedUdpTable` (IPv4+IPv6, sahip PID ile).

### Gizli işlem tespiti (çapraz kontrol)

İşlem listesi bağımsız yöntemlerle alınır:

1. `NtQuerySystemInformation`
2. `CreateToolhelp32Snapshot`
3. `EnumProcesses` (psapi)
4. **Kaba kuvvet PID taraması:** 0 ile üst sınır arasındaki 4'ün katı PID'ler için `OpenProcess` denenir. Listeden kendini çıkaran (DKOM) rootkit'ler genelde açılabilir kalır.
5. TCP/UDP tablolarındaki sahip PID'leri.

Herhangi bir yöntemde canlı görünüp ana listede olmayan işlem "gizli olabilir" diye işaretlenir. Yarış durumlarından (o arada başlayıp biten işlemler) kaçınmak için bir işlemin şüpheli sayılması için iki ardışık taramada da tutarsız çıkması gerekir. Bu mantık Core'da test edilir.

### Şüphe puanı

Core içinde saf fonksiyon. Girdi: imza durumu, yol, ad, ebeveyn, gizlilik bulgusu. Çıktı: puan ve Türkçe gerekçe listesi. Örnek kurallar:

- İmzasız ya da imza geçersiz.
- `%TEMP%`, `AppData`, `Downloads`, `ProgramData`, `Users\Public` altından çalışıyor.
- `svchost.exe`, `lsass.exe`, `csrss.exe` gibi bir sistem adı taşıyor ama `System32` dışından çalışıyor.
- Görünür bir dosyası yok (yol alınamıyor) ama yönetici olarak açılabiliyor.
- Çapraz kontrolde gizli.

### İmza kontrolü

`WinVerifyTrust`, gömülü imza ve katalog imzası (`CryptCATAdmin*`) ile yapılır. İmzalayan adı alınır. Sonuçlar dosya yolu + son değişiklik zamanına göre önbelleğe alınır ve arka planda hesaplanır.

## Arayüz

Sol menüde şu sayfalar var:

- **Genel Bakış:** CPU, GPU, RAM, disk ve ağ kartları, canlı grafikler, sistem bilgisi.
- **İşlemler:** Aranabilir, sıralanabilir tablo (Ad, PID, CPU, RAM, GPU, GPU bellek, Disk, İmza, Risk). Sağ tık menüsü: sonlandır, konumu aç, VirusTotal, yolu kopyala.
- **Güvenlik:** "Tara" düğmesi. Gizli işlemler, şüpheli işlemler ve gerekçeleri. Sınırları anlatan bir bilgi kutusu.
- **Ağ:** Bağlantı tablosu (işlem, yerel/uzak adres, durum).
- **Başlangıç:** Otomatik başlayan öğeler, imza durumu.
- **Ayarlar:** Yenileme aralığı ve tema.

## Geliştiriciye bırakılanlar

Renkler, ikonlar, yerleşimin ayrıntıları ve kesin eşik değerleri.

## Süreç

Her geliştirme adımından sonra iki inceleyici ajan çalıştırılır:

- **Biri doğruluk ve Windows API kullanımına bakar.**
- **Diğeri güvenlik tespiti mantığına ve kullanıcı deneyimine bakar.**

Bulgular tartılıp uygulanır, sonra GitHub'a push edilir.
