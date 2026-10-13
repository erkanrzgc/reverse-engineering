# Reverse-engineering veri seti araştırması — 13 Ekim 2026

## Karar

Başlangıç için **HumanEval-Decompile**, bağımsız ve daha geniş değerlendirme için **DecBench sample-set**, parser/disassembly çeşitliliği için **BinKit** öneriyorum. Şu an model eğitimi gerekmiyor: bu veri setlerinin ilk kullanımı doğruluk benchmark'ı olmalı. Eğitim verisi büyüklüğü, doğru C üretimi için tek başına bir kalite ölçütü değildir.

## Adaylar ve uygunluk

| Veri seti | Ne sağlar? | Bu projeye katkısı | Sınır / lisans durumu |
| --- | --- | --- | --- |
| [HumanEval-Decompile](https://github.com/albertan017/LLM4Decompile) | 164 C problemi; O0–O3 ile 656 değerlendirme kaydı; kaynak, C testleri ve assembly | İlk davranış doğruluğu ve yeniden derleme paketi | Veriler doğrudan PE/ELF input değildir; kaynaklardan yeniden binary üretmek gerekir. Repository LICENSE MIT; model ağırlıklarının lisansı ayrı değerlendirilir. |
| [DecBench dataset](https://huggingface.co/datasets/noelo-lab/decbench-dataset) | Kaynak, ELF/PE binary, source CFG, DWARF temelli type ölçümü, yeniden derleme; sample-set 250 fonksiyon / 223 binary | CFG ve tip doğruluğunu ayrı ölçmek; dış benchmark'a katılmak | Dataset kartı BSD-2-Clause. İçindeki projelerin kaynak/binary lisansları ayrıca korunmalı. Windows REA için native x86/x64 PE alt kümesi gerekir. |
| [ExeBench](https://huggingface.co/datasets/jordiae/exebench) | Gerçek C fonksiyonları, bağımlılıklar ve I/O örnekleri; v1.01 test_real 2.134 kayıt | Basit oyuncak örneklerden gerçek fonksiyonlara geçiş | C fonksiyonlarının özgün repo lisansı metadata'da; ExeBench'in I/O ve boilerplate katkıları MIT. HF viewer custom Python loader nedeniyle kapalı; runtime yükleme uyumluluğu burada denenmedi. |
| [BinKit 2.0](https://github.com/SoftSec-KAIST/BinKit) | 371.928 binary; sekiz mimari, altı optimizasyon, 23 compiler seçeneği | Parser/decoder, fonksiyon bulma, CFG ve dayanıklılık için geniş çeşitlilik | Bir binary similarity benchmark'ı; her fonksiyon için davranış oracle'ı değil. Araç repo lisansı MIT; GNU kaynak projelerin lisansları ayrı. MIPS gibi desteklenmeyen mimarileri ayrı saymak gerekir. |
| [Decompile-Bench](https://github.com/albertan017/LLM4Decompile/tree/main/decompile-bench) | İki milyon source/assembly fonksiyon çifti; HumanEval, MBPP, GitHub2025 değerlendirme splitleri | Daha sonra geniş C/C++ kıyaslaması veya model çalışması | Büyük corpus ilk aşama için gereksiz. GitHub2025 kayıtlarında test alanı boş olabilir; compilation başarı oranını davranış doğruluğu saymamak gerekir. |
| [DecompileBench](https://github.com/vul337/DecompileBench) | OSS-Fuzz tabanlı gerçek proje çıkarımı, recompilation/coverage değerlendirmesi | Daha ileri function extraction ve fuzz temelli değerlendirme yöntemi | Docker/LLVM altyapısı ağır; README build scriptlerinin latest proje commit'ini çekebildiğini belirtiyor. Repo kökünde açık LICENSE bulunmadı; vendoring öncesi koşullar netleştirilmeli. |
| [Pangine disasm-benchmark](https://github.com/pangine/disasm-benchmark) | Compiler temelli disassembly ground-truth üretimi ve yayımlanmış corpus | Instruction/boundary precision-recall ölçümü | x86/x64 ELF disassembly odaklı; C semantiği oracle'ı değil. Repo kökünde açık LICENSE bulunmadı; içeriklerin koşulları ayrı doğrulanmalı. |

**İsim ayrımı:** albertan017'in **Decompile-Bench**, vul337'in **DecompileBench** ve Noelo-Lab'in **DecBench** projeleri ayrı kaynaklardır. Bunların metriklerini ve lisanslarını birleştirmemeliyiz.

## Bu oturumda gerçekten doğrulanan veri

HumanEval'ın mevcut repository ağacındaki küçük legacy değerlendirme JSON'u indirildi ve yalnızca veri olarak okundu:

- Kaynak commit: `85b364bf093eb2ee4f3687cfe38a203fca89f23e`.
- [Sabitlenmiş dosya](https://raw.githubusercontent.com/albertan017/LLM4Decompile/85b364bf093eb2ee4f3687cfe38a203fca89f23e/legacy-test/decompile-eval-executable-gcc-obj.json).
- SHA-256: `d4032271d87eeb37a4190c9096f6dd0c8ef4d65db8df1e42c0265b1fe074bbd8`.
- 656 kayıt, 164 farklı `task_id`; `type` değerleri O0/O1/O2/O3, her birinden 164 kayıt.
- Alanlar: `task_id`, `type`, `c_func`, `c_test`, `input_asm_prompt`. Üç içerik alanı da 656 kayıtta mevcut.
- Kaynaklar arasında floating-point, array ve loop kullanımı görülüyor; bütün corpus mevcut dar scalar lifter tarafından destekleniyor kabul edilemez.

Bu JSON repository'ye eklenmedi; dış kaynak fonksiyonları/binary'leri çalıştırılmadı. Kaynak ve metadata araştırması yapıldı; **bu veri setinde bir decompilation başarı oranı ölçülmedi**.

DecBench dataset revision `815eb96f130b6d2ef7fa600e04669bf20139bf27` için [sample manifest](https://huggingface.co/datasets/noelo-lab/decbench-dataset/resolve/815eb96f130b6d2ef7fa600e04669bf20139bf27/configs/sample-set/manifest.json) okundu: 250 fonksiyon, 223 binary. Büyük arşiv indirilmedi veya çalıştırılmadı.

## Uygulama sırası

1. Yeniden puanlamada doğrulanan dört P1'i kaynak/bayt/native-oracle regressions ile düzelt: flag propagation, loop CFG, call ABI ve stack bellek genişliği.
2. HumanEval'dan 10–20 farklı davranış sınıfı seç; scalar branch, loop, çağrı, array/stack ve signed/unsigned sınır durumları dahil olsun. Desteklenmeyen örnekleri de sonuç tablosunda tut.
3. Kaynak ve testleri GCC/Clang ile O0/O1/O2/O3 altında derle. Windows çalışması MinGW/PE olarak ayrı benchmark varyantı diye etiketlenmeli; orijinal Linux sonuçlarıyla aynı deney sayılmamalı.
4. Aynı binary'nin Rust analizi, REA/Ghidra çıktısı ve bağımsız native test sonucu bir manifestte toplanmalı. PE RVA ile Ghidra loaded VA karşılaştırılırken image base normalize edilmeli.
5. İlk paketten sonra 164 problem × dört optimizasyonu tamamla. DecBench'in 250 fonksiyonluk sample-set'ine format/mimari kapsamını açıkça belirterek geç.
6. ExeBench'ten lisansı/provenance'ı doğrulanmış gerçek fonksiyonlar; BinKit'ten x86/x64 ve ARM/AArch64 parser/decoder alt kümeleri ekle.

## Ölçüm kuralları

Her hedef için source revision/hash, compiler sürümü ve flags, ABI/format/mimari, binary hash, function adresi, decompiler sürümü, süre ve çıktı hash'i tutulmalı. Durumlar ayrı olmalı: unsupported, parse failure, unresolved function, compile failure, native mismatch, timeout ve verified.

Toplam seçilen hedef sayısı, destek oranı, C recompilation oranı ve native test geçiş oranı beraber raporlanmalı. Yalnızca derlenebilen örneklerin yüzdesini genel başarı gibi sunmamalıyız. Timeout veya unsupported kayıtları görünmez şekilde paydadan çıkarılmamalı.

CFG karşılaştırması ve type recovery, davranış testini tamamlar. DecBench'in byte-match/Union skorları, bütün girdilerde semantik eşdeğerlik kanıtı değildir; standart native assertion/I/O testleri ayrıca gereklidir. [DecBench metrik açıklamaları](https://github.com/Noelo-Lab/decbench/blob/14e14b87429043aa06f64e067847ac0a925e41a6/docs/metrics.md).

## Kaynak sürümleri ve doğrulama sınırı

İncelenen HEAD'ler: BinKit `f6565a37049d94a1835dd8459a9d40460daf7fe0`; DecBench araçları `14e14b87429043aa06f64e067847ac0a925e41a6`; vul337/DecompileBench `761c6513b10344f502474f3e5e78c74fd89ab839`; Pangine `11ed4e2a4dcf4bcbcaffc55608f4b651281386ae`. Repo lisans metadata'sı, kök dosya listeleri, maintainer README'leri ve dataset kartları okundu. Büyük dağıtım arşivlerinin erişimi/içeriği ve kurulum scriptlerinin çalışması denenmedi.
