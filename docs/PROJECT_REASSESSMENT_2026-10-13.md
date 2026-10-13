# Güncel değerlendirme — 13 Ekim 2026

**Genel puan: 6,8/10.** Önceki 5,2/10'a göre belirgin ilerleme var. Araç, static triage ve geliştirme/öğrenme için daha kullanışlı; genel ve güvenilir C davranış rekonstrüksiyonu için hâlâ dört doğrulanmış P1 bulunuyor.

İncelenen kaynak HEAD: `73665789837b340bbbfa032ea67bf8f36255c070`, dal `feat/rea-validation`; başlangıç çalışma ağacı temiz. Bu rapor bir dış benchmark skoru değil, aynı kategoriler ve ağırlıklarla yapılan kanıta dayalı mühendislik değerlendirmesidir.

## Puan tablosu

| Alan | Önce /10 | Şimdi /10 | Ağırlık | Güncel gerekçe |
| --- | --- | --- | --- | --- |
| Mimari ve sürdürülebilirlik | 8,0 | 8,0 | %15 | Kütüphane/CLI ayrımı, typed IR, provenance ve deterministik raporlar iyi. Typed/static-address mantığında tekrar ve public AST API genişlemesi var. |
| Format/disassembly/CFG | 5,0 | 6,5 | %15 | Branch hedefleri, prologlar, dynsym/NOBITS ve Mach-O adresleri düzeltildi. Thumb/mixed-mode, sectionless ELF ve universal Mach-O desteği eksik. CFG'nin bulunması C'ye doğru taşınmasını garanti etmiyor. |
| C davranış doğruluğu | 3,0 | 5,0 | %25 | Register genişliği, LEA/IMUL/MOVZX, bazı koşullar ve declarations doğrulandı. Flag/loop/call/stack-alias örneklerinde hâlâ yanlış sonuç veya derleme hatası var. |
| Analiz ve rapor bütünlüğü | 6,0 | 7,5 | %15 | String occurrence, typed IAT/XREF, tail-call, text paketleri ve PE directories iyileşti. Overlay ve bazı format metadata'sı/heuristics eksik. |
| Güvenlik/kaynak dayanıklılığı | 5,5 | 6,5 | %10 | Input/string/artifact sınırları, partial gerekçeleri, child-process deadline ve temiz dependency taraması iyi. Instruction/CFG/AST bellek ve çalışma süresi bütçeleri tam değil. |
| Test ve doğrulama | 6,5 | 7,5 | %10 | 333 Rust + 5 Node testi; gerçek baytlar, GCC ve native oracle, gerçek Ghidra kanıtı var. Dış corpus değerlendirmesi ve yeni kalan P1'lerin kalıcı regressions kapsamı eksik. |
| Belgeler/dağıtım | 4,0 | 8,0 | %10 | Kullanılabilir CLI örnekleri, rapor dosyaları, sürüm/runner/audit düzeltmeleri ve kaynak kanıtları iyi. Uzak CI/release sonucu puan verilirken henüz doğrulanmadı. |
| **Genel** | **5,2** | **6,8** | **%100** | `8×0,15 + 6,5×0,15 + 5×0,25 + 7,5×0,15 + 6,5×0,10 + 7,5×0,10 + 8×0,10 = 6,775` |

## İyi taraflar

- Önceki doğrulanmış hataların önemli bölümü düzeltildi; değişiklikler yalnız test sayısını artırmadı. Örneğin conditional(0/1), AL partial writes, IMUL ve indexed LEA artık kontrollü programda native sonuçla aynı.
- Tool, byte/address provenance'ını daha iyi koruyor. Dynamic base/index operandlarını yanlış IAT/string adresi diye eşleştirmiyor.
- Rapor ve XREF'ler daha tutarlı; yalnız rapor modu kullanılabilir JSON veriyor. Atomik output ve stdout/stderr ayrımı korunuyor.
- REA/Ghidra gerçek sağlayıcı olarak çalıştırıldı; input/sağlayıcı hash ve kimlikleri kontrol ediliyor. Sağlayıcı anlaşması genel doğruluk kanıtı diye sunulmuyor.
- Artifact ve string bütçeleri görünür partial/diagnostic üretiyor; dependency advisories giderildi.
- Yeni araştırma, testi dar örneklerden bağımsız kaynak/test corpus'larına taşıyabilecek somut adaylar sunuyor.

## Kötü taraflar: yeniden üretilen dört P1

Bu örnekler 333 testin yanına eklenen **ayrı inceleme harness'lerinde** çalıştırıldı. Beklenen başarısızlıklar standart test suite'e başarı gibi sayılmadı. Mevcut güncel rlib kullanıldı; root ajan native sonuçları ve derleme hatasını yeniden doğruladı.

| Bulgular | Native / beklenen | Üretilen C | Etki |
| --- | --- | --- | --- |
| `cmp ecx,0; nop; je zero` | input=1 → 1 | 0 | NOP flags'i değiştirmez; adjacent-compare recovery dışı durumda koşul literal `1`e düşüyor. |
| `inc eax; dec ecx; jnz again` | input=3 → 3 | 1 | Back-edge C'de bir comment'e dönüşüyor; döngü bir kez çalışıyor. Aggressive optimization bunu düzeltmiyor. |
| Bilinen `callee(rcx)` çağrısı | caller için sonuç 6 | `callee()`; GCC too-few-arguments | Argüman ve callee dönüşünü RAX'a bağlayan ABI/dataflow yok; sonrasında tanımsız yerel RAX da okunabiliyor. |
| Aynı stack offset'ine dword ardından byte yazımı | `0x11223355` | `0x55` | Farklı genişlikler tek `local_8` scalar'a indirgeniyor; byte yazımı üst byte'ları yok ediyor. |

Kaynak konumları: [structure.rs](../src/decompiler/structure.rs) `branch_condition_with_cfg`, `recovered_condition_ir`, `structure_function_with_cfg`; [lifter.rs](../src/decompiler/lifter.rs) `instruction_to_statement`, `write_operand`, `operand_to_expr`; [signatures.rs](../src/decompiler/signatures.rs) return inference.

### Yapısal sorun

Unsupported/unknown semantics için yalnızca asm comment veya `/* condition ... */ 1` üretmek yeterli değil. Bu, okunabilir ama çalışan yanlış C oluşturabiliyor. `AnalysisStatus::complete` pipeline'ın tamamlandığını gösteriyor; davranışın doğruluğunu göstermiyor. Genel decompiler iddiasının önündeki ana engel bu.

## Doğrulama ve kanıtlar

- Fresh locked suite tekrar çalıştırıldı: **333 Rust testi başarılı**, ignored/failed yok. Node runner **5/5** başarılı. fmt ve all-target/all-feature clippy `-D warnings` tekrar başarılı.
- Üç native karşılaştırma, yalnızca bizim kontrollü x64 baytlarımızın Windows executable memory'ye alınması ve GCC'nin derlediği C ile karşılaştırılmasıyla yapıldı. Üçüncü taraf corpus binary'leri çalıştırılmadı.
- Call örneği GCC C11 syntax kontrolünde beklenen too-few-arguments hatası verdi.
- [Native sonuçlar](reviews/2026-10-13-rescore/root-native-results.txt), [üretilen C](reviews/2026-10-13-rescore/root-generated.txt), [call diagnostics](reviews/2026-10-13-rescore/root-calls-diagnostics.txt), [Rust harness](reviews/2026-10-13-rescore/review.rs), [C oracle](reviews/2026-10-13-rescore/oracle.c), [suite logu](reviews/2026-10-13-rescore/tests.txt).

Sınır: Bu yeniden değerlendirme, önceki audit ve değişikliklerin üzerine hedefli residual incelemedir; bütün kombinasyonların bağımsız denetimi değildir. Dış dataset başarı yüzdesi henüz ölçülmedi. Mevcut public code bu dört P1 giderilmeden güvenilir source-recovery ürünü olarak değerlendirilmemeli.

## Sıradaki öncelikler

1. P1 flag/loop/ABI/stack-width hatalarını düzelt ve unknown koşulları çalışan sabit koşula çevirmeyi kaldır.
2. [Veri seti araştırmasındaki](DATASET_RESEARCH_2026-10-13.md) HumanEval pilotunu ölç; başarısız ve unsupported örnekleri açık paydada tut.
3. DecBench sample-set, ExeBench ve BinKit alt kümeleriyle kapsamı genişlet; format/ABI/toolchain farklarını etiketle.
4. Instruction sayısı, CFG/AST bellek ve süre bütçeleri; raw-file overlay provenance; Thumb/endian/slice desteği üzerinde çalış.

Push için mevcut feature dalı kullanılacak. Bu rapor, hedefli geliştirmeleri ve kalan sorunları birlikte yayınlar; varsayılan master'a merge veya release onayı anlamına gelmez.
