"""QR-code phishing (quishing): image/inline image mein chhupa QR; link text scanner ko nazar nahi aata.
OpenCV optional hai (pip install opencv-python-headless pillow). Na ho to layer chup-chaap band.
Decompression-bomb se bachao: pehle PIL se sirf header se size dekhte hain, bari image decode nahi hoti."""
from __future__ import annotations

import io
import logging

log = logging.getLogger("engine.qr")
MAX_PIXELS = 12_000_000
MAX_IMAGES = 5
MAX_BYTES = 3_000_000


def available() -> bool:
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def decode_qr_urls(images: list[tuple[str, bytes]]) -> list[str]:
    """Images se sirf http(s) QR payloads. Kabhi raise nahi karta."""
    try:
        import cv2
        import numpy as np
        from PIL import Image
    except ImportError:
        return []
    found: list[str] = []
    det = cv2.QRCodeDetector()
    for _name, data in images[:MAX_IMAGES]:
        if len(data) > MAX_BYTES:
            continue
        try:
            w, h = Image.open(io.BytesIO(data)).size
            if w * h > MAX_PIXELS or w < 20 or h < 20:
                continue
            img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            if img is None:
                continue
            for variant in (img, cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST)):
                text, _pts, _ = det.detectAndDecode(variant)
                if text:
                    if text.lower().startswith(("http://", "https://")):
                        found.append(text.strip()[:500])
                    break
        except Exception:  # noqa: BLE001
            log.info("QR decode skip")
    return list(dict.fromkeys(found))
