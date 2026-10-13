# REA destekli geliştirme — 13 Ekim 2026

Çalışma dalı: `feat/rea-validation`. Başlangıç: `e5070ab`.

## Sonuç

Rust çekirdeğindeki yeniden üretilen doğruluk sorunları düzeltildi. REA 6.4.0, Ghidra 12.1.4 ve JDK 21 ile gerçek Windows PE karşılaştırması çalıştırıldı. REA bir Rust bağımlılığına dönüştürülmedi; yerel ve isteğe bağlı doğrulama aracı olarak kullanılıyor.

## Değişiklikler

- Lifter → CFG arasında instruction adresleri korunuyor. Koşullu dönüşler kaybolmuyor; parametreler yerel değişken olarak tekrar tanımlanmıyor.
- Desteklenen x64 tamsayı örneklerinde LEA, üç operandlı IMUL, kısmi register yazımları, MOVZX, register genişlikleri, signed/unsigned karşılaştırmalar ve indeksli adres parametreleri düzeltildi. LOCK işlemleri düz aritmetiğe çevrilmiyor; prefixed RET korunuyor.
- ARM branch/call hedefleri, BEQ/BLNE/bx lr; x86 LOOP/JCXZ ve prefix metadata; çok instruction içeren prologlar düzeltildi. Çakışan executable section adresleri açık hatayla reddediliyor.
- ELF `.dynsym` tanımları korunuyor, `.bss` dosya verisi olarak okunmuyor; Mach-O export adresleri image base ile düzeltiliyor.
- Dynamic base/index taşıyan bellek operandları IAT veya string adresi olarak yanlış çözümlenmiyor. Aynı string değerinin ayrı adresleri korunuyor; aynı adresteki alternatif encodingler C’de çift global tanım oluşturmuyor.
- Gerçek tail-call ilişkileri call graph ve XREF’lerde tutarlı; fonksiyon içi döngü jump’ları tail-call sayılmıyor. BCrypt API sınıflandırması genişletildi.
- Artifact sayısı ve yakalanan byte miktarı sınırlı. Manifest kesilme gerekçesini içeriyor; engine `partial` ve `artifact_limit_exceeded` üretiyor. String sınırının tam dolması tek başına yanlış `partial` oluşturmuyor.
- Eksik text raporları, `import_xrefs.json` ve `pe_directories.json` tamamlandı. `--only-report` kullanılabilir JSON döndürüyor. README ve CI/release komutları güncellendi.
- `anyhow` 1.0.104 ve `crossbeam-epoch` 0.9.20 ile taramada çıkan advisories giderildi. cargo-audit 0.22.2 mevcut CVSS 4 verisini okuyabiliyor; CI unsound uyarılarını da reddediyor.

## Doğrulama

| Kontrol | Sonuç |
| --- | --- |
| `cargo test --locked --all-features` | 333 başarılı: 245 unit + 88 integration; başarısız/ignored yok |
| Yeni Rust regressions | Önceki 276 teste göre 57 ek test |
| `node --test scripts/rea-compare.test.mjs` | 5 başarılı |
| `cargo fmt -- --check` | Başarılı |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Başarılı |
| `cargo build --locked --release` | Başarılı; çalışma alanındaki release executable güncel |
| cargo-audit 0.22.2, `--file Cargo.lock --deny unsound` | Başarılı |
| Üretilen C | Gerçek byte regressions içinde GCC derleme/çalıştırma; bütün kontrollü PE çıktısı ayrıca derlendi ve native oracle ile karşılaştırıldı |
| Gerçek REA/Ghidra | Aynı PE üzerinde overview ve conditional pseudocode; sağlayıcı kimliği ve input SHA-256 kontrol ediliyor |

Bağımsız native oracle ve Rust’ın ürettiği C aynı sonuçları verdi:

| Örnek | Beklenen / native / üretilen C |
| --- | --- |
| conditional(0) | 0 |
| conditional(1) | 1 |
| IMUL(3, 7) | 21 |
| RAX=0x1234, AL=0x56 | 4694 = 0x1256 |
| MOVZX(EAX, AL=0x34) | 52 = 0x34 |
| LEA(base=100, index=3, scale=8, disp=-8) | 116 |

Ghidra conditional fonksiyonunda sıfır için `return 0`, diğer değerler için `return 1` yollarını gösteriyor. İki araç da altı fonksiyon buluyor. Rust 11 string occurrence, Ghidra 8 defined string bildiriyor; farklı extraction/definition yöntemleri kullanıldığı için bu sayılar eşdeğer metrik olarak değerlendirilmemeli.

Komutlar, SHA-256’lar, ham sağlayıcı çıktıları ve doğrulama logları [kanıt dizininde](reviews/2026-10-13-rea/) saklanıyor. [Karşılaştırma manifesti](reviews/2026-10-13-rea/comparison.json) çalışmanın kanonik kaydıdır. [Çalıştırma talimatları](REA_VALIDATION.md) araç kurulumunu ve kapsamını açıklıyor.

## Sınırlar ve devam noktaları

Bu sonuçlar bütün instruction setinin veya her binary’nin doğru C’ye çevrildiğini kanıtlamaz. Genel loop/switch/flag propagation, ABI/call argument recovery, stack aliasing, SIMD ve sıra dışı addressing henüz tam doğrulanmış değildir. Thumb/mixed-mode ve big-endian ARM desteklenmiyor; metadata tespit edebildiğinde açık hata verilir. ARM32 Mach-O mode-aware decoding gelene kadar reddediliyor. PE overlay, ELF import function isimleri/sectionless parsing, Mach-O universal slice seçimi ve doğrulanmış Python marshal carving sonraki işlerdir. Çok büyük kod bölümleri için instruction/CFG/AST bellek bütçeleri de eklenmelidir.

Modüller arası incelemelerde bulunan prefix, signature, string global, boş report-only çıktı ve process-deadline sorunları test edilip giderildi. Ek genel bağımsız son inceleme, ajan kullanım kotası nedeniyle tamamlanamadı; yukarıdaki test, derleme, güvenlik taraması ve gerçek sağlayıcı kontrolleri yerel olarak tamamlandı. Linux/macOS runtime ve GitHub CI/release job’ları bu Windows oturumunda çalıştırılmadı.

Önceki 5.2/10 puan tarihsel audit sonucudur; bu değişikliklerden sonra bütün kategoriler yeniden puanlanmış değildir.
