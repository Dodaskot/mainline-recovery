#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Portable, per-user Android SettingsProvider values for system and secure namespaces."""
import re
from xml.etree import ElementTree as ET

import android_package_registry as registry


# Numeric preferences from Android's SystemSettings and SecureSettings backup lists.
BOOLEAN = ('0', '1')
SYSTEM = dict.fromkeys(('accelerometer_rotation', 'screen_brightness_mode', 'sound_effects_enabled',
                        'haptic_feedback_enabled', 'dtmf_tone', 'lockscreen_sounds_enabled',
                        'vibrate_when_ringing', 'show_password', 'auto_caps', 'auto_replace',
                        'auto_punctuate', 'status_bar_show_battery_percent', 'master_mono'), BOOLEAN)
SYSTEM.update(time_12_24=('12', '24'), pointer_speed=range(-7, 8), screen_off_timeout=range(1, 2**31),
              font_scale=(0.5, 3.0))
SYSTEM.update(dict.fromkeys(('alarm_vibration_intensity', 'media_vibration_intensity', 'notification_vibration_intensity',
                             'ring_vibration_intensity', 'haptic_feedback_intensity', 'hardware_haptic_feedback_intensity'),
                            range(4)))
SECURE = dict.fromkeys(('accessibility_display_inversion_enabled', 'high_text_contrast_enabled',
                        'accessibility_captioning_enabled', 'accessibility_large_pointer_icon',
                        'show_ime_with_hard_keyboard', 'accessibility_autoclick_enabled'), BOOLEAN)
SECURE.update(long_press_timeout=range(100, 5001), accessibility_autoclick_delay=range(0, 5001),
              accessibility_captioning_font_scale=(0.25, 4.0), tts_default_rate=range(10, 601),
              tts_default_pitch=range(10, 601))
RULES = {'system': SYSTEM, 'secure': SECURE}


def valid(namespace, name, value):
    rule = RULES[namespace].get(name)
    if rule is None or not isinstance(value, str) or not 1 <= len(value) <= 16:
        return False
    if isinstance(rule, range):
        return bool(re.fullmatch(r'-?[0-9]+', value)) and int(value) in rule
    if isinstance(rule[0], float):
        return bool(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value)) and rule[0] <= float(value) <= rule[1]
    return value in rule


def read(data, namespace):
    return read_rules(data, RULES[namespace], namespace)


def read_rules(data, rules, namespace=None):
    """The values of the named settings in one SettingsProvider file (text XML or ABX)."""
    if not 0 < len(data) <= registry.MAX_BYTES:
        raise ValueError('Unsupported settings file size')
    if data.startswith(b'ABX\0'):
        root = registry.binary_tree(data, fragment=True)
    else:
        if b'\0' in data or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
            raise ValueError('Unsupported settings XML')
        xml = re.sub(r'^<\?xml\s+[^?]*\?>', '', data.decode('utf-8-sig'), count=1)
        root = ET.fromstring('<document>' + xml + '</document>')
    stores = root.findall('settings')
    if len(stores) != 1:
        raise ValueError('Expected one SettingsProvider settings section')
    values, seen = {}, set()
    for setting in stores[0].findall('setting'):
        name, value = setting.get('name'), setting.get('value')
        if name not in rules:
            continue
        if name in seen:
            raise ValueError('Repeated Android preference')
        seen.add(name)
        if valid(namespace, name, value) if namespace else value in rules[name]:
            values[name] = value
    return values


def valid_bundle(data):
    return (isinstance(data, dict) and data.keys() == RULES.keys() and any(data.values())
            and all(isinstance(items, dict) and all(valid(ns, key, value) for key, value in items.items())
                    for ns, items in data.items()))
