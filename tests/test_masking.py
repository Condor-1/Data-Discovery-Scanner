from sensitive_data_scanner.detection.masking import mask_sensitive_value


def test_mask_sensitive_value_keeps_default_prefix() -> None:
    assert mask_sensitive_value("sk_live_abcdefghijklmnop") == "sk_live_****************"


def test_mask_sensitive_value_masks_short_values_fully() -> None:
    assert mask_sensitive_value("secret") == "******"


def test_mask_sensitive_value_can_keep_suffix() -> None:
    assert mask_sensitive_value("abcdef123456", visible_prefix=3, visible_suffix=2) == "abc*******56"


def test_mask_sensitive_value_handles_empty_value() -> None:
    assert mask_sensitive_value("") == ""
