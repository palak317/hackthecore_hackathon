import math
import os
from typing import Any, Dict, List

import numpy as np

try:
    import cv2
except ImportError:  # pragma: no cover
    cv2 = None

try:
    import pytesseract
except ImportError:  # pragma: no cover
    pytesseract = None


def _clamp_score(value: float) -> int:
    """Keep all risk scores inside the 0-100 range."""
    return max(0, min(100, int(round(value))))


def _calculate_entropy(image: np.ndarray) -> float:
    """Measure randomness in the image. Hidden data often pushes entropy upward."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    histogram = cv2.calcHist([gray], [0], None, [256], [0, 256]).ravel()
    total_pixels = gray.size
    if total_pixels == 0:
        return 0.0

    probabilities = histogram / total_pixels
    return -sum(float(p) * math.log2(float(p)) for p in probabilities if p > 0)


def _lsb_randomness_score(image: np.ndarray) -> float:
    """Inspect least-significant bits because simple steg tools often modify them."""
    flat_pixels = image.reshape(-1)
    if flat_pixels.size == 0:
        return 0.0

    lsb_bits = flat_pixels & 1
    ones_ratio = float(np.mean(lsb_bits))
    transitions = float(np.mean(lsb_bits[:-1] != lsb_bits[1:])) if lsb_bits.size > 1 else 0.0

    ratio_balance = max(0.0, 1.0 - abs(0.5 - ones_ratio) * 2.0)
    transition_balance = max(0.0, 1.0 - abs(0.5 - transitions) * 2.0)
    return ((ratio_balance * 0.55) + (transition_balance * 0.45)) * 100.0


def _file_size_anomaly_score(file_path: str, image: np.ndarray) -> float:
    """Compare file size to pixel count. Strange ratios can suggest hidden payloads."""
    height, width = image.shape[:2]
    if height <= 0 or width <= 0:
        return 0.0

    file_size = os.path.getsize(file_path)
    pixels = width * height
    bytes_per_pixel = file_size / float(pixels)

    if bytes_per_pixel >= 2.25:
        return 100.0
    if bytes_per_pixel >= 1.5:
        return 75.0
    if bytes_per_pixel >= 0.95:
        return 45.0
    return 10.0


def _extract_text(image: np.ndarray) -> str:
    """Use OCR to read visible text from screenshots, banners, and posters."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    denoised = cv2.GaussianBlur(gray, (3, 3), 0)
    _, thresholded = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    text = pytesseract.image_to_string(thresholded)
    return " ".join(text.split())


def analyze_image_for_steg(file_path: str) -> Dict[str, Any]:
    """
    Analyze one image in two ways:
    1. OCR to read visible text
    2. Steganography checks to estimate whether hidden data may exist
    """
    if cv2 is None or pytesseract is None:
        raise RuntimeError("Image analysis dependencies missing: install opencv-python and pytesseract")

    image = cv2.imread(file_path, cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError("Unable to read image for OCR/steganography analysis")

    reasons: List[str] = []
    extracted_text = _extract_text(image)
    entropy = _calculate_entropy(image)
    lsb_score = _lsb_randomness_score(image)
    size_score = _file_size_anomaly_score(file_path, image)

    entropy_score = 100.0 if entropy >= 7.6 else 70.0 if entropy >= 7.25 else 20.0
    if entropy >= 7.25:
        reasons.append("High entropy")

    if lsb_score >= 85.0:
        reasons.append("Unusual LSB pattern")

    if size_score >= 45.0:
        reasons.append("File size anomaly")

    steg_score = _clamp_score((entropy_score * 0.4) + (lsb_score * 0.35) + (size_score * 0.25))
    return {
        "extracted_text": extracted_text,
        "steg_score": steg_score,
        "steg_risk_score": steg_score,
        "steg_flag": steg_score >= 60,
        "reasons": reasons,
    }
