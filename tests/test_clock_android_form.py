"""The hardware clock in Android's form (year - 1968) read by the mt6397 driver: back to the real time."""
from datetime import datetime, timedelta, timezone
import unittest

import clock


def as_read_by_kernel(real):
    """What this kernel shows for a hardware clock Android set to REAL (until 2035: a register below 68)."""
    register = real.replace(year=real.year - 68)  # the driver takes register r as 1900 + r
    return register + timedelta(days=46751)       # then moves it into its window


class AndroidForm(unittest.TestCase):
    def test_observed_on_two_phones(self):
        read = datetime(2086, 11, 18, 21, 17, 4, tzinfo=timezone.utc)
        self.assertEqual(clock.from_android_form(read.timestamp()),
                         datetime(2026, 11, 19, 21, 17, 4, tzinfo=timezone.utc).timestamp())

    def test_round_trip_including_leap_days(self):
        for real in (datetime(2026, 11, 19, 21, 17, 4), datetime(2027, 1, 1), datetime(2028, 2, 29, 12),
                     datetime(2028, 3, 1), datetime(2035, 12, 31, 23, 59, 59)):
            real = real.replace(tzinfo=timezone.utc)
            with self.subTest(real=real):
                self.assertEqual(clock.from_android_form(as_read_by_kernel(real).timestamp()), real.timestamp())

    def test_other_clocks_are_left_alone(self):
        for read in (datetime(2026, 11, 19), datetime(2027, 6, 1), datetime(2120, 1, 1), datetime(1970, 1, 2)):
            self.assertIsNone(clock.from_android_form(read.replace(tzinfo=timezone.utc).timestamp()))
        now = datetime(2026, 11, 19, 12, tzinfo=timezone.utc).timestamp()
        self.assertEqual(clock.from_hardware(set_clock=False, now=now), {'set': False, 'reason': 'plausible'})
        self.assertEqual(clock.from_hardware(set_clock=False, now=datetime(2120, 1, 1, tzinfo=timezone.utc).timestamp()),
                         {'set': False, 'reason': 'unknown form'})

    def test_start_up_sets_the_meant_time(self):
        read = as_read_by_kernel(datetime(2026, 11, 19, 20, 9, 53, tzinfo=timezone.utc)).timestamp()
        self.assertEqual(clock.from_hardware(set_clock=False, now=read),
                         {'set': True, 'utc': int(datetime(2026, 11, 19, 20, 9, 53, tzinfo=timezone.utc).timestamp())})


if __name__ == '__main__':
    unittest.main()
