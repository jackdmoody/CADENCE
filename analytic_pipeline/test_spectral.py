"""
Regression tests for the spectral confirmation step (periodicity._fft_dominant_period).

Before v3.1 the Welch PSD ran on the IAT sequence with fs=1.0, so every pair with
>= 60 observations returned (64.0, 1.0) whether it beaconed or not.
"""
import numpy as np
import pytest

from analytic_pipeline.periodicity import _fft_dominant_period

RNG = np.random.default_rng(1)


def _beacon(period, jitter, n):
    return np.cumsum(period * (1 + jitter * RNG.uniform(-1, 1, n)))


@pytest.mark.parametrize("period,jitter,n", [(300, 0.0, 500), (300, 0.15, 500),
                                             (3600, 0.2, 200), (21600, 0.1, 120)])
def test_beacons_have_concentrated_spectrum_at_their_period(period, jitter, n):
    est, ratio = _fft_dominant_period(_beacon(period, jitter, n), 60.0)
    assert ratio > 0.15
    assert est == pytest.approx(period, rel=0.05)


@pytest.mark.parametrize("ts", [
    np.cumsum(RNG.exponential(300, 500)),
    np.cumsum(RNG.uniform(1, 10_000, 500)),
    np.cumsum(RNG.lognormal(5, 1.5, 500)),
])
def test_aperiodic_traffic_has_flat_spectrum(ts):
    _, ratio = _fft_dominant_period(ts, 60.0)
    assert ratio < 0.10


def test_periods_are_in_seconds_not_samples():
    est, _ = _fft_dominant_period(_beacon(900, 0.05, 300), 60.0)
    assert est == pytest.approx(900, rel=0.05)   # the old code returned 64.0 here


def test_short_series_returns_null():
    assert _fft_dominant_period(np.array([0.0, 10.0, 20.0]), 60.0) == (0.0, 0.0)
