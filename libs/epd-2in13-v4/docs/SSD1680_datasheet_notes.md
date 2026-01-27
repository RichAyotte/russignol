# SSD1680 Controller Datasheet Notes

This information was retrieved because it was missing from the `2.13inch_e-Paper_V4_Specification.pdf`.

## Reset Pulse Timing (`RES#` pin)

*   **Minimum Pulse Width**: 10 microseconds (µs). The `RES#` pin must be held low for at least this long.
*   **Recommended Power-On Reset**: >= 10 milliseconds (ms). For the initial power-on, holding the pin low for at least 10ms is recommended for maximum reliability.
*   **Typical Operational Reset**: Many libraries use a value between 2ms and 20ms for waking the device from sleep.

A duration of 20ms is a safe and robust value for all reset conditions.
