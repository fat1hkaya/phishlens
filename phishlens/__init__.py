"""PhishLens - phishing e-mail analysis toolkit for SOC analysts."""

from phishlens.analyzer import analyze_bytes, analyze_file

__version__ = "1.0.0"
__all__ = ["analyze_bytes", "analyze_file", "__version__"]
