# Engine metrics (Phase 1) - PADHNE SE PEHLE

**In numbers par bharosa mat karo.** Bundled model **synthetic template data** par train hua hai
(`engine/dataset.py`), kyunke asli phishing corpus (Nazario, SpamAssassin, Enron, apne reported
emails) is environment mein maujood nahi tha. Ye model pipeline chalane ka demo hai, production
ka detector nahi. Production se pehle `python -m engine.train --csv real_data.csv` se dobara
train karo aur ye file nayi numbers se update karo.

## 1. Synthetic held-out (threshold 0.5, sirf ML layer)
| Test set | n | Precision | Recall | False-positive rate |
|---|---|---|---|---|
| Unseen phrasing (same families, naye templates) | 280 | 0.833 | 1.000 | **0.080** (16 legit galat flag) |
| Unseen families (poori nayi families) | 280 | 1.000 | 1.000 | 0.000 |

Ye test data bhi usi template generator se bana hai, isliye asli duniya mein kahin kharab hoga.
Asal sabaq: ML akeli legit emails ko ~8% galat flag kar rahi hai, isi liye design mein ML akeli
kabhi PHISHING nahi bana sakti (heuristics ki corroboration lazmi).

## 2. Hand-written sanity set (`python -m engine.evaluate`, poora engine, bina network)
18 emails (8 phishing, 10 legit, jin mein hard negatives: OTP, password reset, promo, e-statement).
Result: 18/18 sahi, 0 false positives, 0 legit "suspicious". **Ye emails maine khud likhe hain** aur
model/heuristics unhi usoolon par bane hain, isliye ye optimistic hai. Ye regression guard hai,
accuracy ka daawa nahi.

## 3. Jo abhi test NAHI hua
- VirusTotal asli API se (khaas kar `sha256` URL-id mode: VT ki canonical form se miss ho sakta hai;
  zarurat ho to `id_mode="base64"`).
- OpenAI asli API se (sirf mock transport se).
- Threat-feed downloader (URLhaus/OpenPhish): `LocalFeed` lookup bana hai aur test hua hai, magar
  feed download/refresh job Phase 3/4 mein aayega.
- Asli inbox ka prior: training 50/50 hai, asli inbox mein phishing 1-2% hoti hai, to ML ki
  probabilities zyada hoti hain (prior shift). Asli data par threshold/calibration dobara tune karo.
- Real-world Roman Urdu/Urdu phishing ka bara corpus: abhi sirf chhote template samples.
