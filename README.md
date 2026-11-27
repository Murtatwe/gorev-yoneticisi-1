# Görev Yöneticisi

Windows 11 için modern bir görev yöneticisi. Bilgisayarınızda neyin, ne kadar kaynak kullandığını gösterir ve Windows Görev Yöneticisi'nden **gizlenen** programları yakalamaya çalışır.

## İndirme ve çalıştırma

1. [Son sürüm](https://github.com/Murtatwe/gorev-yoneticisi-1/releases/tag/latest) sayfasını açın.
2. **GorevYoneticisi.exe** dosyasını indirin.
3. Çift tıklayın. Windows yönetici izni ister; **Evet** deyin (tüm işlemleri görebilmek için gerekli).

Kurulum gerekmez, .NET yüklemeniz gerekmez.

> Windows SmartScreen "Windows bilgisayarınızı korudu" uyarısı verebilir, çünkü dosya ticari bir sertifikayla imzalı değil. **Ek bilgi → Yine de çalıştır** ile açabilirsiniz.

## Neler var?

| Sayfa | Ne gösterir |
|---|---|
| **Genel Bakış** | CPU, RAM, GPU, disk ve ağ kullanımı; canlı grafikler; çekirdek başına CPU; en çok kaynak kullanan programlar |
| **İşlemler** | Her programın CPU, bellek, GPU, GPU belleği ve G/Ç kullanımı; dijital imzası ve risk durumu; komut satırı; sonlandırma, dosya konumunu açma, VirusTotal'de arama |
| **Güvenlik** | Gizlenen işlem taraması ve dikkat isteyen programların gerekçeleriyle listesi |
| **Ağ** | Hangi programın nereye bağlı olduğu |
| **Başlangıç** | Windows açılırken kendiliğinden çalışan her şey: kayıt defteri, Başlangıç klasörü, zamanlanmış görevler (gizlenmiş olanlar dahil), servisler, sürücüler, WMI abonelikleri, tarayıcıya zorla yüklenen eklentiler |
| **Ayarlar** | Yenileme hızı, tarama sıklığı, tema |

## Gizli işlemler nasıl bulunuyor?

Çalışan işlemler birbirinden bağımsız yollarla sayılır ve sonuçlar karşılaştırılır:

- Windows'un normal işlem listesi (Görev Yöneticisi'nin de kullandığı).
- Olası her işlem numarasının (PID) tek tek denenmesi.
- Ağ bağlantılarının sahibi olan işlemler.

Normal listede görünmeyip çalıştığı doğrulanan bir işlem, kendini gizliyor demektir. Yanlış alarmı önlemek için bir tutarsızlığın art arda iki taramada görülmesi gerekir.

Riskli programlar şu ipuçlarıyla işaretlenir, her işaretin gerekçesi yazılır:

- İmzasız ya da imzası bozuk dosyalar.
- Geçici klasörlerden veya İndirilenler'den çalışan programlar.
- Sistem dosyası taklitleri (ör. `svch0st.exe`, yanlış klasördeki `lsass.exe`).
- Görünmez karakterli ya da çift uzantılı adlar (`fatura.pdf.exe`).

### Sınırlar (dürüstçe)

Windows çekirdeğine yerleşmiş gelişmiş rootkit'ler her programdan saklanabilir; bu program da dahil. "Risk" bir tahmindir, kesin teşhis değildir. Şüpheli bir şey görürseniz **VirusTotal'de ara** düğmesini kullanın ve Microsoft Defender ile tam tarama yapın.

## Sorun bildirme

Bir hata olursa `%LOCALAPPDATA%\GorevYoneticisi\hata.log` dosyasını paylaşın (Ayarlar → Klasörü aç).

## Geliştirme

- C# / .NET 8, WPF, [WPF-UI](https://github.com/lepoco/wpfui)
- `src/GorevYoneticisi.Core`: platformdan bağımsız mantık (risk puanı, gizli işlem tespiti, ayrıştırıcılar), `tests/` altında birim testleri
- `src/GorevYoneticisi.App`: Windows API'leri ve arayüz
- Her push'ta GitHub Actions Windows'ta derler, testleri çalıştırır, uygulamayı gerçekten açıp her sayfayı gezen bir duman testi yapar ve "Son sürüm"ü günceller.

```bash
dotnet test tests/GorevYoneticisi.Core.Tests
```

```bash
dotnet publish src/GorevYoneticisi.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```
