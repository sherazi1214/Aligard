# Retraining + evaluation (Phase 4)

Bundled `model.joblib` abhi bhi **synthetic template data** par hai. Asli numbers aur asli model
neeche ke qadmon se aate hain. Test set ko sirf `eval_real` chhoota hai.

## Qadam 0: data jama karo
| Source | Label | Kaise do |
|---|---|---|
| Apni reported phishing + legit mails | 1 / 0 | CSV, columns `text,label` (ya `subject,body,label`) |
| Nazario phishing corpus | 1 | `.mbox` files |
| SpamAssassin public corpus (`spam`, `easy_ham`, `hard_ham` folders) | 1 / 0 | folder, har file ek raw email |
| Enron | 0 | CSV (`message` column) |
| PhishTank / OpenPhish | n/a | URL list: text model ke liye nahi, neeche "URL feeds" dekho |

Apni mails sab se qeemti hain: Roman Urdu aur Pakistani brands (JazzCash, Easypaisa, BISP) sirf wahin milte hain.

## Qadam 1: corpus banao (dedup + leak-free split)
```bash
python -m engine.corpus build --out data/ \
  --csv my_mails.csv:mine \
  --mbox nazario.mbox:nazario:1 \
  --spamassassin-dir spam:spamassassin:1 --spamassassin-dir easy_ham:spamassassin:0 \
  --enron-csv enron.csv:enron:0
```
- Exact duplicates (URL/number badal kar bani copies samet) hat jate hain; aik hi text ke do alag labels hon to dono nikal diye jate hain.
- Near-duplicates (5-word shingles, Jaccard >= 0.8) ek cluster banate hain aur **poora cluster ek hi taraf** jata hai.
- `data/manifest.json` mein har file ka sha256 hai; `train.csv/val.csv/test.csv` badli to load hi nahi hoga.
- Sab se sakht test: `--test-source nazario` (poora dataset test mein, model ne kabhi dekha nahi).

## Qadam 2: models ka muqabla (sirf val par)
```bash
python -m engine.compare --data data/ --save engine/artifacts/model.joblib
```
Variants: `nb-word` (purana), `lr-word`, `lr-char`, `lr-word-char`. Winner = FPR 1% par sab se ooncha recall.
`--save` winner ko train+val par dobara train karke likhta hai (test nahi chhoota).

## Qadam 3: test par naapo + METRICS.md update
```bash
python -m engine.eval_real --data data/ --model engine/artifacts/model.joblib \
  --prevalence 0.02 --engine --write-metrics
```
Threshold curve, recall@FPR, calibration, aur **asli inbox ke 1-2% prior par precision**. Synthetic test par `--write-metrics` mana hai.

## Qadam 4: weights/thresholds data se
```bash
python -m engine.tune_weights --data data/ --max-fpr 0.005 --max-suspicious-fpr 0.05
```
`ml_weight` (40/60 wala sawal), thresholds aur ML cap val par chune jate hain, test par aik baar parkhe jate hain.
Reputation / sandbox / LLM tune **nahi** hote (network layers, CSV mein un ke outputs nahi).

## Zaroori batein
- **sklearn version**: model us version se load hota hai jisse train hua (`requirements.txt`: 1.9.1). Retrain wahi par karo jahan deploy hoga, warna `ModelLoadError`.
- **Text-only CSV ki hadd**: headers/auth/anchors nahi, is liye heuristics adhi chalti hain. Final parakh raw `.eml` par karo.
- **Prior shift**: training ~50/50 hoti hai, inbox 1-2% phishing. Probabilities zyada nikalti hain; isi liye `--prevalence` wali precision dekho.

## URL feeds (PhishTank / OpenPhish)
```bash
python -m engine.corpus urls-to-feed phishtank_urls.txt feeds/phishtank.txt
```
Phir `LocalFeed.from_file("phishtank", "feeds/phishtank.txt")` reputation layer mein.
