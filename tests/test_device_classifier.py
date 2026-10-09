from core.device_classifier import classify_device
from core.vendor_lookup import lookup_vendor


def test_classify_by_hostname_iphone():
    # A specific brand label (not just the broad "Smartphone" category)
    # is expected now that hostname hints are brand-specific — see
    # core/device_classifier.py's _HOSTNAME_HINTS docstring.
    assert classify_device(hostname="Johns-iPhone", vendor="Apple") == "iPhone"


def test_classify_by_hostname_router():
    assert classify_device(hostname="TP-Link-Router", vendor="TP-Link") == "Router"


def test_classify_by_vendor_iot_fallback():
    assert classify_device(hostname="unknown-device", vendor="Philips (Hue)") == "IoT"


def test_classify_unknown_when_no_hints():
    assert classify_device(hostname=None, vendor=None) == "Unknown"


def test_vendor_lookup_known_prefix():
    assert lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"


def test_vendor_lookup_unknown_prefix():
    # 02:xx:xx is a locally-administered address (the "locally
    # administered" bit is set in the second hex digit): by definition
    # it is never a real IEEE-assigned global OUI, so this is a prefix
    # genuinely absent from data/oui_vendors.txt — unlike 00:00:00,
    # which is a real, historically-assigned Xerox Corporation block and
    # so is NOT a valid "unknown vendor" test case.
    assert lookup_vendor("02:DE:AD:11:22:33") == "Unknown"


def test_vendor_lookup_invalid_mac():
    assert lookup_vendor("not-a-mac") == "Unknown"