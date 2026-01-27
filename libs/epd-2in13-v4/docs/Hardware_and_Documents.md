# Hardware and Document Summaries

This file provides a summary of the hardware components and the corresponding PDF documents in this directory.

## E-Paper Display

### `2.13inch_e-Paper_V4_Specification.pdf`

This document contains the specifications for the 2.13-inch e-paper display.

*   **Display Controller:** SSD1680Z8
*   **Key Hardware:**
    *   **N-Channel MOSFET:** Si1308EDL
    *   **Diodes:** MBR0530
*   **Resolution:** 250x122 pixels
*   **Interface:** 3-wire/4-wire SPI

## Touch Controller

### `GT1151QM_Datasheet-EN.pdf`

This is the datasheet for the GT1151Q capacitive touch chip.

*   **Function:** 10-point capacitive touch controller with gesture wake-up.
*   **Interface:** I2C
*   **Key Features:**
    *   Supports 5" to 6" touch panels.
    *   16 drive channels and 29 sensing channels.
    *   Glove and pen support.
    *   Low power consumption with multiple operating modes.
    *   On-chip MPU for touch and gesture processing.
    *   Self-calibration for environmental changes.

### `GT1151Q_Application-EN.pdf`

This document is a programming guide for the GT1151Q touch controller. It provides details on:

*   **I2C Communication:** Register maps, read/write operations, and timing diagrams.
*   **Operating Modes:** Descriptions of Normal, Green, Gesture, and Sleep modes.
*   **Gesture Recognition:** How to configure and read gesture data.
*   **Register Maps:** Detailed information on configuration, coordinate, and gesture registers.

## Controller Notes

### `SSD1680_datasheet_notes.md`

This file contains specific details about the SSD1680 controller that were not in the main e-paper specification PDF.

*   **Reset Pulse Timing:**
    *   **Minimum:** 10µs
    *   **Recommended for Power-On:** >= 10ms
    *   **Typical for Wake-up:** 2ms - 20ms
    *   A safe value for all resets is 20ms.
