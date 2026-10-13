# Proje incelemesi — 10 Ekim 2026

**Genel puan: 5,2/10 (52/100).** Mimari ve geliştirme altyapısı güçlü. En büyük açık, gerçek talimatlardan üretilen C'nin davranış doğruluğu; bunu raporların eksikliği ve dağıtım akışındaki sorunlar izliyor. Proje eğitim, disassembly ve ilk analiz için yararlı bir temel sunuyor. Güvenilir davranış rekonstrüksiyonu için aşağıdaki doğruluk sorunları çözülmeli.

## Kapsam ve yöntem

- İncelenen yerel sürüm: `e5070ab1f640f889c6b9f8553d78d280b5bc812b`, paket sürümü `0.2.0`, dal `master`.
- Başlangıç çalışma ağacı temizdi; yerel dal `origin/master` bilgisinden 25 commit ilerideydi. Uzak deponun güncel CI sonucu alınmadı.
- İzlenen 45 Rust dosyası, toplam 15.812 satır; bu sayı testleri ve gömülü Mach-O örneğini de içeriyor. Kaynak modülleri, testler, şema, bağımlılık tanımları, fuzz hedefleri, benchmarklar, README, mimari/güvenlik belgeleri ve CI/release akışları tarandı.
- Mimari, parser/disassembly, decompiler ve analiz/rapor katmanları ayrı incelemelerle ele alındı. Önemli bulgular küçük sentetik girdilerle tekrar üretildi.
- İlk test çalıştırması taşınmış klasörün eski derleme önbelleğini kullandı: entegrasyon testleri eski `Desktop/deCompiler` yolunu arıyordu. Ayrı ve temiz bir hedef dizininde yeniden derleme bu çevresel hatayı giderdi. Bu durum kaynak kod hatası olarak puanlanmadı.
- Kritik tekrar üretimler temiz derlemenin kütüphanesine karşı da çalıştırıldı. Analiz edilen üçüncü taraf executable'lar çalıştırılmadı; yalnızca analiz aracı ve oluşturduğumuz küçük doğrulama programları çalıştırıldı.
- Uygulama koduna düzeltme yapılmadı. Bu rapor ve metin kanıtları inceleme çıktısıdır.

## Puanlama

Puanlar geliştirme eforunu veya fikir değerini değil, mevcut uygulamanın doğrulanmış durumunu ölçer. Ürünün ana vaadi C üretimi olduğu için davranış doğruluğu en yüksek ağırlığa sahip.

| Alan | Puan /10 | Ağırlık | Gerekçe |
|---|---:|---:|---|
| Mimari ve sürdürülebilirlik | 8,0 | %15 | İnce CLI, kütüphane sınırı, modüller, tipli sonuçlar; bazı kullanılmayan/tekrarlanan yardımcılar var. |
| Format, disassembly ve kontrol akışı | 5,0 | %15 | Olgun altyapı kütüphaneleri; ARM, bazı x86 dalları, export adresleri ve fonksiyon bulmada doğrulanmış açıklar. |
| C üretiminin davranış doğruluğu | 3,0 | %25 | Basit dallar, register genişliği, LEA/IMUL ve parametre bildirimlerinde yanlış sonuçlar. |
| Analiz ve rapor bütünlüğü | 6,0 | %15 | Kullanışlı rapor yapısı; string/XREF, tail-call, overlay ve dosya paketi eksikleri. |
| Güvenlik ve kaynak dayanıklılığı | 5,5 | %10 | Girdi/string sınırları ve hata sınırı iyi; artifact ve genişleme bütçeleri eksik. |
| Test ve doğrulama kalitesi | 6,5 | %10 | 276 test geçiyor; gerçek üretim sırasını ve davranış eşdeğerliğini ölçen testler eksik. |
| Kullanım belgeleri ve dağıtım | 4,0 | %10 | README komutları eski; audit komutu ve macOS release hedefi sorunlu. |
| **Ağırlıklı genel sonuç** | **5,2** | **%100** | `8×0,15 + 5×0,15 + 3×0,25 + 6×0,15 + 5,5×0,10 + 6,5×0,10 + 4×0,10` |

## Güçlü taraflar

1. `AnalysisEngine` analiz politikasını CLI'den ayırıyor. Sonuç seçimi ve kaynak limitlerinin tek bir sınırdan yönetilmesi geliştirmeyi kolaylaştırıyor.
2. ELF/PE/Mach-O için Goblin, x86 için iced-x86, ARM için Capstone kullanılması iyi bir temel. Sorunların önemli kısmı bu kütüphanelerin çevresindeki yorumlama katmanında.
3. Sürümlü JSON zarfı, deterministik sıralama, tipli hata kodları ve `complete/partial` ayrımı otomasyon için yararlı.
4. Dosya başına atomik yazım, stdout ile stderr ayrımı ve başarısız paket yazımında stdout'un boş kalması iyi ele alınmış.
5. C string/comment/identifier temizliği ve taşma/sıfıra bölme korumalı constant folding için hedefli testler var.
6. Runtime kanıtları ve davranış göstergeleri açıklamalarla sunuluyor; Dart AOT ve kaynak kurtarma sınırları belgelerde belirtilmiş. CyberChef bağlantıları oluşturuluyor, kendiliğinden uzak çözümleme yapılmıyor.
7. Test örneklerinin kökeni/lisansı, katkı rehberi, güvenlik belgesi, fuzz hedefleri, MSRV kontrolü ve platform matrisi mevcut.

## Öncelikli, doğrulanmış bulgular

Burada **P1**, sıradaki geliştirme turunda öncelikli ele alınması gereken davranış/işletim sorununu; **P2**, olağan düzeltme sırasındaki işlev veya doğruluk sorununu gösterir. Bir güvenlik açığı/CVE derecelendirmesi yapılmamıştır.

### 1. P1 — Gerçek IR yolu basit koşullu dalları kaybediyor

[lifter.rs:127](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/lifter.rs:127) bazı talimatları kaynak adresi bulunmayan expression'lara çeviriyor. [structure.rs:275](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/structure.rs:275) yalnızca `InlineAsm` adreslerini indeksliyor; blok eşleştirmesi ilk ve son talimat adreslerini istiyor.

Gerçek baytlardan çözülen `cmp ecx,0; je zero; mov eax,1; ret; zero: xor eax,eax; ret` için AST'de **0 if, 2 üst düzey return** oluştu. Üretilen ve derlenen C, hem `conditional(0)` hem `conditional(1)` için **1** döndürdü; talimat dizisinin beklenen sonuçları **0 ve 1**. Aggressive optimizasyon ikinci kolu ilk return'den sonraki erişilemez kod sanıp tamamen siliyor ([optimization.rs:244](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/optimization.rs:244)).

**Düzeltme yönü:** Her lifted statement'ta talimat adresini/aralığını korumak; CFG üzerinden erişilebilirlik kanıtlanmadan kod silmemek; gerçek decoder → lifter → structurer → optimizer sırasını test etmek.

### 2. P1 — Desteklenen talimatlar yanlış anlamla C'ye çevriliyor

[lifter.rs:249](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/lifter.rs:249), [lifter.rs:369](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/lifter.rs:369) ve register normalizasyonu gerçek operand genişliğini/anlamını kaybediyor.

| Talimat | Gözlenen çeviri | Beklenen anlam |
|---|---|---|
| `lea rax,[rbp-8]` | `rax = rax + local_8` | Stack slotunun adresini ata. |
| `imul eax,ecx,7` | `rax = rax * rcx` | `ecx` ile 7'yi çarp. |
| `mov rax,[rbp+rcx*8-8]` | `rax = local_8` | İndeksli bellek erişiminde `rcx*8` etkisini koru. |
| `mov rax,1234h; mov al,56h` | Sonuç `0x56` | Üst bitleri koru: sonuç `0x1256`. |
| `mov rax,1234h; movzx eax,al` | Sonuç `0x1234` | Byte'ı sıfırla genişlet: sonuç `0x34`. |

Kısmi register örneğinde üretilen C çalıştırılarak `0x56` sonucu ayrıca doğrulandı. Bu sorunlar genel SSA eksikliğinden önce, desteklenmiş gibi çevrilen basit talimatlarda ortaya çıkıyor.

**Düzeltme yönü:** Opcode ve operand biçimine özel lifting, register genişliği/byte konumu takibi; doğru temsil edilemeyen biçimlerde açık disassembly fallback'i.

### 3. P1 — Parametre kurtarma aynı ismi yerel değişken olarak tekrar bildiriyor

[engine.rs:714](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/engine.rs:714) önce structuring, sonra signature recovery yapıyor. [structure.rs:905](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/structure.rs:905) henüz parametre bulunmadığından `rcx` için local bildirimi ekliyor; sonraki aşama aynı ismi parametre yapıyor.

`8B C1 C3` → `mov eax,ecx; ret` çıktısı:

```c
uint64_t parameter(uint64_t rcx) {
    uint64_t rax;
    uint64_t rcx;
    rax = rcx;
    return rax;
}
```

GCC C11 kontrolü `'rcx' redeclared as different kind of symbol` hatası verdi. Basit ELF örneğinin C'si sözdizimi kontrolünü geçti; sorun her dosyada değil, bu üretim yolunda.

**Düzeltme yönü:** Parametreleri local bildirimlerinden önce kurtarmak veya bildirimleri imza sonrası uzlaştırmak.

### 4. P1 — ARM kontrol akışı ve çalışma modu eksik

[arm.rs:85](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/disasm/arm.rs:85) ARM32 `beq` dalını control-flow olarak tanımıyor; aynı sınıf onu conditional branch kabul ediyor. Gerçek `beq #0x100c` örneğinin CFG'sinde alınan dal kenarı kayboldu.

[functions.rs:211](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/functions.rs:211) ARM çağrı hedeflerini kullanmıyor. AArch64 `bl #0x1008; ret; ret` örneğinde iki fonksiyon yerine yalnızca giriş fonksiyonu bulundu.

[arm.rs:14](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/disasm/arm.rs:14) ARM32'yi daima A32 modunda çözüyor. Thumb `push/pop` baytları ilgisiz bir `stclt` talimatına dönüştü; PE ARMNT de aynı ARM etiketine eşleniyor.

**Düzeltme yönü:** Format bilgisinden mode/endian seçimi, typed branch/call hedefleri ve decoder'dan CFG'ye gerçek ARM/Thumb örnekleri.

### 5. P1 — Bazı x86 dalları ve prefix'li return kayboluyor

[x86.rs:48](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/disasm/x86.rs:48) mnemonic'i biçimlendirilmiş metinden ayırıyor; [x86.rs:70](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/disasm/x86.rs:70) yalnızca bazı branch türlerinin hedefini alıyor.

- `E2 FE C3` (`loop 0x1000; ret`): control-flow false, hedef yok, döngü kenarı yok.
- `E3 FE C3` (`jrcxz`): conditional kabul ediliyor, fakat hedef yok; taken edge kayıp.
- `F3 C3 90` (`rep ret; nop`): mnemonic `rep`, return false; return sonrası talimat aynı bloğa giriyor.

**Düzeltme yönü:** Biçimlendirilmiş metin yerine decoder'ın talimat/flow türlerini esas almak.

### 6. P1 — Runtime artifact sayısı sınırlandırılmıyor

[runtime_artifacts.rs:162](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/runtime_artifacts.rs:162) her cookie için yeni artifact kaydı oluşturuyor. Kaynak limitleri yalnızca giriş byte sayısını ve string sayısını sınırlıyor.

**32.777 byte'lık** kontrollü veri **4.097 artifact** oluşturdu. Daha büyük girdilerde bellek ve JSON çıktısı büyüyebilir. Büyük ölçekli bellek tüketimi deneyi yapılmadı; etki küçük örnekte doğrulanan çoğalma ve kaynak kod üzerinden değerlendirilmiştir. Benzer birikme bytecode adaylarında ve örtüşen section kopyalarında da değerlendirilmeli.

**Düzeltme yönü:** Artifact/adres/talimat sayısı, toplam payload/rapor boyutu ve section genişlemesi için ayrı bütçeler; limitte tipli `partial` tanısı.

### 7. P1 — CI bağımlılık tarama komutu geçersiz seçenek içeriyor

[ci.yml:31](C:/Users/erkanrzgc/Desktop/reverse-engineering/.github/workflows/ci.yml:31) `cargo audit --locked` çalıştırıyor. Workflow'un hedeflediği cargo-audit 0.21.2'nin [resmî CLI tanımı](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.21.2/cargo-audit/src/commands/audit.rs) ve [üst komut tanımı](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.21.2/cargo-audit/src/commands.rs) `--locked` seçeneğini içermiyor. Seçenek `cargo install` için anlamlı, `cargo audit` alt komutu için değil.

Bu bulgu sürüme ait kaynak üzerinden doğrulandı; yerelde cargo-audit kurulu olmadığından komutla bir bağımlılık taraması yapılmadı. Bağımlılıklar için temiz/güvenli sonucu verilmemiştir.

**Düzeltme yönü:** `cargo audit` veya `cargo audit --file Cargo.lock` kullanmak; kurulum sürümünü ve job çıktısını ayrıca doğrulamak.

### 8. P1 — Release matrisi kullanım dışı macOS runner'a bağlı

[release.yml:27](C:/Users/erkanrzgc/Desktop/reverse-engineering/.github/workflows/release.yml:27) `macos-13` kullanıyor. GitHub'ın [resmî kaldırma duyurusu](https://github.com/actions/runner-images/issues/13046) bu etiketi Aralık 2025'te destek dışı bırakıyor. İnceleme tarihi itibarıyla bu hedef geçersiz; `publish` tüm build matrisine bağlı olduğundan Intel macOS işi yayın akışını engelleyebilir. Bir release tetiklenmedi.

**Düzeltme yönü:** x86_64 hedefini uygun desteklenen Intel runner'a taşımak; Apple Silicon hedefinin runner yaşam döngüsünü de güncellemek. Mevcut sağlayıcı duyurusu Intel için `macos-15-intel` etiketini öneriyor.

### 9. P2 — Dinamik dolaylı çağrı yanlış API adıyla eşleşiyor

[report.rs:1048](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/report.rs:1048) ve [lifter.rs:162](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/decompiler/lifter.rs:162) RIP dışındaki bellek operandında ilk hex sayıyı mutlak adres sanıyor.

`FF 90 00 40 00 00` → `call qword ptr [rax+4000h]`, IAT haritasında `0x4000` bulununca `kernel32.dll!CreateFileW` olarak raporlandı. Oysa etkin adres `rax` değerine bağlı. Bu yanlış API ve davranış yorumuna yol açabilir.

**Düzeltme yönü:** Typed memory operand kullanmak; yalnızca dinamik base/index bulunmayan mutlak veya çözülebilir RIP-relative operandları eşlemek.

### 10. P2 — Aynı string'in ikinci konumu ve bazı karakter kodlamaları kayboluyor

[strings.rs:120](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/strings.rs:120) adres yerine değer üzerinden tekilleştiriyor; rapor string'leri adres üzerinden eşliyor. `same\0same\0` yalnızca bir string verdi; ikinci konuma başvuran fonksiyonun string XREF sayısı **0** oldu.

Ayrıca UTF-8 `Türkçe`, tek sayılı offset'te UTF-16LE ve UTF-16BE örnekleri bulunamadı. Mevcut yol esas olarak printable ASCII ve çift hizalı ASCII içerikli UTF-16LE'yi işliyor.

**Düzeltme yönü:** Her adres/encoding oluşumunu korumak, gösterim tekilleştirmesini ayrıca yapmak; desteklenen encoding seçeneklerini uygulamak veya belgelerde daraltmak.

### 11. P2 — Tail-call kayıtları graph ve XREF ile tutarlı değil

[report.rs:878](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/report.rs:878) her unconditional jump'ı tail-call kabul ediyor; aynı fonksiyon içindeki geri sıçrama bile tail-call olarak listelendi. Buna karşılık graph/caller indeksleri yalnızca normal çağrıları kullanıyor.

Gerçek fonksiyonlar arası tail jump: tail-call kaydı **1**, graph kenarı **0**, callee caller sayısı **0**. IAT jump thunk'ı API'ye çözüldüğü halde import caller listesi boş kaldı.

**Düzeltme yönü:** Fonksiyon içi dalları dışlamak; gerçek tail transferlerini edge kind bilgisiyle graph/XREF/import indekslerine eklemek.

### 12. P2 — PE overlay'deki runtime kanıtları analiz sınırına girmiyor

[runtime_artifacts.rs:13](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/runtime_artifacts.rs:13) girdisi ham dosyayı/offset'leri taşımıyor. Runtime taraması section byte'larıyla sınırlı. Geçerli PE örneğinin sonuna eklenen `_MEIPASS`, `PYZ-00.pyz` ve CArchive işaretleri için runtime/artifact sayısı **0**; 1.052 dosya byte'ından yalnızca 512 section byte'ı analiz edildi.

Bu, section dışındaki paketlenmiş payload'lar için önemli bir kapsam açığıdır. PyInstaller'ın [resmî archive okuyucusu](https://github.com/pyinstaller/pyinstaller/blob/develop/bootloader/src/pyi_archive.c) cookie'yi dosyada geriye doğru arıyor. Buradaki deney bir gerçek PyInstaller paketi değil, overlay görünürlüğü testidir.

**Düzeltme yönü:** Ham dosya/overlay aralıklarını file-offset kökeniyle taşımak; aday tespiti ile doğrulanmış archive/PYC çıkarımını ayırmak.

### 13. P2 — ELF ve Mach-O metadata'sında doğrulanmış adres/veri hataları var

- [elf.rs:100](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/binary/elf.rs:100) export için yalnızca `.symtab` okuyor. `.dynsym` içindeki `helloWorld/main/_init/_fini` korunduğu halde stripped örneğin export listesi boş kaldı.
- [elf.rs:65](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/binary/elf.rs:65) `SHT_NOBITS` section'ını dosya verisi gibi okuyor. Kontrollü `.bss` örneği gerçek bellekte bulunmayan `FAKE` byte'larını içerdi.
- [macho.rs:115](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/binary/macho.rs:115) image-relative export offset'ini VA olarak sunuyor. 283 byte'lık örnekte giriş/section `0x100000100`, export `_f` ise `0x100` çıktı; fonksiyon export adıyla eşleşmedi.

**Düzeltme yönü:** Her formatın adres uzayını açık tanımlamak; dynamic symbol'leri, section türünü ve image base'i doğru kullanmak. Universal Mach-O ve section header'sız ELF kapsamı ayrıca belirtilmeli.

### 14. P2 — Fonksiyon prologue fallback'i çalışmıyor; örtüşen section iç hata üretiyor

[functions.rs:45](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/functions.rs:45) birkaç talimatı kapsayan `push; mov` byte dizilerini tek talimatın byte'larıyla karşılaştırıyor. Entry/export/call seed'i olmayan gerçek x86 ve x64 frame-prologue örneklerinde **0 fonksiyon** bulundu.

[functions.rs:123](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/functions.rs:123) adres sırası ile stream index sırasını eşit varsayıyor. 292 byte'lık örtüşen executable section örneği `slice index starts at 26 but ends at 13` panic'i oluşturdu. Engine bunu yakalayıp **InternalFailure** döndürüyor; süreç seviyesinde yakalanmamış çökme olarak değerlendirilmemeli.

**Düzeltme yönü:** Çok talimatlı prologue eşleştirme; section sınırlarını, örtüşmeleri ve sıralamayı açık yönetme.

### 15. P2 — README'nin kullanım örnekleri güncel CLI ile çalışmıyor

[README.md:114](C:/Users/erkanrzgc/Desktop/reverse-engineering/README.md:114) ve devamında `-i`, `--json`, `--only-report`, `--extract-runtime-artifacts` gösteriliyor. Mevcut CLI `analyze <input> --format ...` kullanıyor. README biçimindeki çağrı **exit 2 / unexpected argument '-i'** verdi.

Bugün çalışan örnek:

```text
reverse-engineering analyze binary.exe --format json --output result.json --report-dir reports --artifacts-dir artifacts
```

CLI daima `OutputSelection::all()` seçiyor; kütüphanenin report-only seçimi CLI'de sunulmuyor. README'nin 250 test bilgisi de güncel toplam 276 ile uyuşmuyor.

**Düzeltme yönü:** Tüm örnekleri gerçek `--help` ile eşlemek; gerekli seçimleri CLI'ye sunmak; örnek komutları smoke test olarak doğrulamak.

### 16. P2 — Vaat edilen rapor paketinde dosyalar ve metadata eksik

[output.rs:71](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/output.rs:71) yalnızca JSON bileşenlerinin bir bölümünü yazıyor. ELF ve temiz derleme PE denemelerinde şu vaat edilen çıktılar oluşmadı:

- `report.txt`
- `behavior_report.txt`
- `import_xrefs.json` (import XREF bilgisi başka JSON içinde mevcut; ayrı dosya eksik)
- `pe_directories.json` (parser metadata'yı çıkarıyor, engine/report sınırına taşımıyor)
- `runtime_report.txt`

**Düzeltme yönü:** Paketin kesin dosya sözleşmesini belirlemek; her bileşeni production writer'a bağlamak; gereken dosyaları ve içeriklerini integration testte doğrulamak.

## Testlerin geçmesi neden yeterli olmadı?

[golden_decompile.rs:8](C:/Users/erkanrzgc/Desktop/reverse-engineering/tests/golden_decompile.rs:8) gerçek decoder yerine `ir: None` taşıyan elde hazırlanmış talimatlar ve doğrudan `InlineAsm` AST'si kullanıyor. Bu testler gerçek lifter'ın adres kaybını atlıyor. İmza testi de production akışındaki local declaration sırasını kullanmıyor.

Contract testleri deterministik çıktıyı ve alanları iyi ölçüyor; mevcut JSON Schema ise iç rapor/artifact nesneleri için ayrıntılı tip/alan sözleşmesi tanımlamıyor. Paket testleri birkaç dosyanın varlığını doğruluyor, README'nin tam çıktı listesini doğrulamıyor. Fuzz hedefleri parser/disassembler düzeyinde; engine, CFG, lifting, rapor birikmesi ve writer sınırları kapsanmıyor.

En yüksek değerli yeni kontroller: gerçek byte'lardan tam pipeline koşullu dal/parametre testleri, desteklenen C altkümesi için derleme ve küçük davranış karşılaştırmaları, ARM/Thumb CFG örnekleri, adres/encoding bazlı string XREF'leri, gerçek tail edge'leri, artifact bütçesi, overlay örnekleri ve paket sözleşmesi. Test sayısını artırmak yerine bu boşlukları kapatmak öncelikli.

## İkinci sıra bakım ve kapsam işleri

- `BCryptEncrypt` ve `BCryptGenRandom` için crypto insight bulunmadı; API matcher, `bcrypt` family prefix'ini desteklenen suffix eşleşmeleriyle karıştırıyor ([report.rs:1305](C:/Users/erkanrzgc/Desktop/reverse-engineering/src/analysis/report.rs:1305)).
- Signed ve unsigned branch'ler aynı karşılaştırmaya, register/local türleri çoğunlukla `uint64_t`'ye dönüşüyor. Çağrı parametreleri ve dönüş değerleri de dar heuristiklerle ele alınıyor. Bunlar için sınırlar ve belirsizlik çıktıya yansıtılmalı.
- PYC dosyaları güçlü biçim doğrulaması olmayan carving adayları; payload sınırı/truncation ve güven düzeyi manifestte açık olmalı.
- PatternMatcher ve TypeInference production akışında kullanılmıyor. Pattern matcher'ın adres/regex sorunlarını çözmeden bu modülleri ürün yeteneği saymamak gerekir.
- `CGeneratorConfig` seçeneklerinin bir kısmı etkisiz; variadic/array/function-pointer bildirimleri ve import/internal/global isimlerin ortak benzersizliği gözden geçirilmeli.
- Benchmarklar küçük string ve talimat örnekleriyle sınırlı; tam engine, farklı boyutlar, output seçimleri ve bellek tüketimi için ölçüm yok.
- Release ve CI toolchain hedefleri, action pinleme yaklaşımı ve release öncesi kalite/onay kapıları tutarlı hale getirilmeli. Mevcut release işi tag'i doğruluyor; Cargo sürümü ile tag eşitliğini veya bu commit'in CI başarısını ayrıca zorunlu kılmıyor.

## Doğrulama sonuçları ve sınırlar

Ortam: Windows, `rustc/cargo 1.95.0`, `x86_64-pc-windows-gnu`. Ayrı temiz hedef dizini kullanıldı.

| Kontrol | Sonuç |
|---|---|
| `cargo fmt -- --check` | Geçti. |
| Temiz hedefte `cargo clippy --locked --all-targets --all-features -- -D warnings` | Geçti; uyarı yok. |
| Temiz hedefte `cargo test --locked --all-features` | **244 birim + 32 entegrasyon = 276 test geçti.** |
| Temiz hedefte `cargo build --locked --release` | Geçti. |
| Temiz hedefte `cargo bench --locked --no-run` | Geçti; benchmark executable'ları derlendi, ölçüm kampanyası çalıştırılmadı. |
| Gerçek ELF ve PE'den çıktı/rapor paketi | Üretildi; eksik dosyalar yukarıda kaydedildi. |
| ELF örneğinin C sözdizimi | GCC C11 kontrolünü geçti. |
| Parametre örneğinin C sözdizimi | Beklenen bug tekrar üretildi: aynı parametre/local adı derleme hatası. |
| Kontrollü branch/register davranış denemeleri | Yanlış sonuçlar tekrar üretildi. |
| Yerel `notepad.exe` analizi | Tamamlandı: 360.448 byte, 48.038 talimat, 672 fonksiyon, 703 string. |

Notepad'in temiz **debug** derlemesiyle JSON üretimi tek ölçümde yaklaşık **6,7 saniye** sürdü; JSON yaklaşık **5,54 MB**. Bu bir release performans benchmarkı veya doğruluk kanıtı değildir. `complete` burada pipeline'ın tanısız bitmesini gösterir; üretilen kodun anlamının doğru olduğunu garanti etmez.

Linux/macOS üzerinde çalıştırma, Windows MSVC release hedefi, Rust 1.87 ile gerçek derleme, gerçek paketlenmiş runtime corpus'u ve süreli fuzz kampanyası bu incelemede yapılmadı. `cargo audit` yerelde kurulu değildi; güncel bağımlılık advisory taraması tamamlanmış sayılmaz. Büyük ölçekli bellek tükenmesi denenmedi.

## Önerilen uygulama sırası

1. C davranışı: kaynak adresleri/CFG, doğru opcode ve register semantiği, parametre/local uzlaştırma; bunların gerçek pipeline kontrolleri.
2. Kontrol akışı: ARM/Thumb mode ve branch/call hedefleri, x86 prefix/loop sınıflandırması, fonksiyon sınırları.
3. Dayanıklılık: artifact/payload/talimat/section genişleme bütçeleri ve örtüşen section doğrulaması.
4. Rapor doğruluğu: typed IAT çözümü, adres bazlı string'ler, tail graph/XREF, ELF/Mach-O metadata ve overlay.
5. Kullanıma hazırlık: README/CLI/paket sözleşmesi, audit komutu, release runner'ları ve daha gerçekçi fixture/corpus.

Bu sırada önce mevcut temel yeteneklerin doğruluğunu güçlendirmek, sonra kapsamı genişletmek en yüksek katkıyı sağlar. SSA, GUI veya yeni runtime aileleri gibi büyük özellikler ilk dört grubun önüne geçmemeli.

Metin kanıtları: [inceleme kanıt dizini](C:/Users/erkanrzgc/Desktop/reverse-engineering/docs/reviews/2026-10-10).
