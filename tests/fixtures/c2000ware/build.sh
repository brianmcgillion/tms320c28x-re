#!/usr/bin/env bash
# Build C2000Ware f28004x device_support examples with cl2000.
# Requires: fetch.sh has been run first, cl2000 in PATH.
# Run: nix develop -c bash tests/fixtures/c2000ware/build.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$SCRIPT_DIR/sdk"
BUILD_DIR="$SCRIPT_DIR/build"
CGT_DIR="$(dirname "$(which cl2000)")/.."

# Device support paths
DEV="$SDK_DIR/device_support/f28004x"
COMMON_SRC="$DEV/common/source"
COMMON_INC="$DEV/common/include"
HEADERS_INC="$DEV/headers/include"
HEADERS_SRC="$DEV/headers/source"
HEADERS_CMD="$DEV/headers/cmd"
LINKER_CMD="$DEV/common/cmd/28004x_generic_ram_lnk.cmd"

if [ ! -d "$DEV" ]; then
    echo "SDK not found. Run fetch.sh first:"
    echo "  nix develop -c bash tests/fixtures/c2000ware/fetch.sh"
    exit 1
fi

echo "=== Building C2000Ware f28004x examples ==="
echo "Compiler: cl2000 $(cl2000 --compiler_revision)"
echo "SDK:      $DEV"
echo "Output:   $BUILD_DIR"
echo

mkdir -p "$BUILD_DIR"

# Fix case-sensitivity: TI headers use mixed case, cl2000 on Linux is case-sensitive
if [ ! -e "$COMMON_INC/f28x_project.h" ] && [ -e "$COMMON_INC/F28x_Project.h" ]; then
    ln -sf F28x_Project.h "$COMMON_INC/f28x_project.h"
fi

# Common support source files needed by all examples
SUPPORT_SRCS=(
    "$COMMON_SRC/f28004x_codestartbranch.asm"
    "$COMMON_SRC/f28004x_sysctrl.c"
    "$COMMON_SRC/f28004x_gpio.c"
    "$COMMON_SRC/f28004x_piectrl.c"
    "$COMMON_SRC/f28004x_pievect.c"
    "$COMMON_SRC/f28004x_defaultisr.c"
    "$COMMON_SRC/f28004x_usdelay.asm"
    "$HEADERS_SRC/f28004x_globalvariabledefs.c"
)

# Add optional support files only if they exist
for extra in f28004x_adc.c f28004x_cputimers.c f28004x_dma.c; do
    [ -f "$COMMON_SRC/$extra" ] && SUPPORT_SRCS+=("$COMMON_SRC/$extra")
done

COMPILER_FLAGS=(
    -v28
    --abi=eabi
    --float_support=fpu32
    -ml                             # Large memory model
    -mt                             # Unified memory
    -O0                             # No optimization for readable disassembly
    -g                              # Debug symbols
    --define=CPU1
    --define=_LAUNCHXL_F280049C
    -I"$COMMON_INC"
    -I"$HEADERS_INC"
    -I"$CGT_DIR/include"
)

LINKER_FLAGS=(
    -z
    --rom_model
    --entry_point=code_start
    --stack_size=0x200
    --heap_size=0x100
    -i"$CGT_DIR/lib"
    -l"rts2800_fpu32_eabi.lib"
    "$LINKER_CMD"
    "$HEADERS_CMD/f28004x_headers_nonbios.cmd"
)

# Examples to build: (name, source_file)
declare -A EXAMPLES=(
    ["led_blink"]="$DEV/examples/led/led_ex1_blinky.c"
    ["adc_epwm"]="$DEV/examples/adc/adc_ex1_soc_epwm.c"
    ["sci_echoback"]="$DEV/examples/sci/sci_ex1_echoback.c"
    ["gpio_setup"]="$DEV/examples/gpio/gpio_ex1_setup.c"
    ["timer_cputimers"]="$DEV/examples/timer/timer_ex1_cputimers.c"
    ["ecap_apwm"]="$DEV/examples/ecap/ecap_ex1_apwm.c"
    ["dma_transfer"]="$DEV/examples/dma/dma_ex1_gsram_transfer.c"
    ["spi_loopback"]="$DEV/examples/spi/spi_ex1_loopback.c"
    ["interrupts_prio"]="$DEV/examples/interrupts/interrupts_ex1_sw_prioritization.c"
)

success=0
fail=0

for name in "${!EXAMPLES[@]}"; do
    src="${EXAMPLES[$name]}"
    out="$BUILD_DIR/${name}.out"
    map="$BUILD_DIR/${name}.map"
    obj_dir="$BUILD_DIR/obj_${name}"

    echo -n "Building $name... "

    if [ ! -f "$src" ]; then
        echo "SKIP (source not found: $src)"
        continue
    fi

    mkdir -p "$obj_dir"

    if cl2000 "${COMPILER_FLAGS[@]}" \
        --obj_directory="$obj_dir" \
        "$src" \
        "${SUPPORT_SRCS[@]}" \
        "${LINKER_FLAGS[@]}" \
        -m"$map" \
        -o"$out" 2>"$BUILD_DIR/${name}.log"; then
        echo "OK ($(wc -c < "$out") bytes)"
        success=$((success + 1))
    else
        echo "FAILED"
        tail -20 "$BUILD_DIR/${name}.log"
        fail=$((fail + 1))
    fi
done

echo
echo "=== f28004x results: $success OK, $fail failed ==="

# ── F2833x (F28335) examples ──

DEV33="$SDK_DIR/device_support/f2833x"
if [ -d "$DEV33" ]; then
    echo
    echo "=== Building C2000Ware f2833x (F28335) examples ==="

    COMMON33_SRC="$DEV33/common/source"
    COMMON33_INC="$DEV33/common/include"
    HEADERS33_INC="$DEV33/headers/include"
    HEADERS33_SRC="$DEV33/headers/source"
    HEADERS33_CMD="$DEV33/headers/cmd"
    LINKER33_CMD="$DEV33/common/cmd/28335_RAM_lnk.cmd"

    # Case-sensitivity fix for f2833x
    if [ ! -e "$COMMON33_INC/dsp28x_project.h" ] && [ -e "$COMMON33_INC/DSP28x_Project.h" ]; then
        ln -sf DSP28x_Project.h "$COMMON33_INC/dsp28x_project.h"
    fi

    SUPPORT33_SRCS=(
        "$COMMON33_SRC/DSP2833x_CodeStartBranch.asm"
        "$COMMON33_SRC/DSP2833x_ADC_cal.asm"
        "$COMMON33_SRC/DSP2833x_SysCtrl.c"
        "$COMMON33_SRC/DSP2833x_Gpio.c"
        "$COMMON33_SRC/DSP2833x_PieCtrl.c"
        "$COMMON33_SRC/DSP2833x_PieVect.c"
        "$COMMON33_SRC/DSP2833x_DefaultIsr.c"
        "$COMMON33_SRC/DSP2833x_usDelay.asm"
        "$COMMON33_SRC/DSP2833x_CSMPasswords.asm"
        "$HEADERS33_SRC/DSP2833x_GlobalVariableDefs.c"
    )
    # Add commonly needed support files (NOT McBSP — has delay_loop collision)
    for extra in DSP2833x_Adc.c DSP2833x_CpuTimers.c DSP2833x_DMA.c \
                 DSP2833x_ECap.c DSP2833x_EPwm.c DSP2833x_MemCopy.c; do
        [ -f "$COMMON33_SRC/$extra" ] && SUPPORT33_SRCS+=("$COMMON33_SRC/$extra")
    done

    # F2833x SDK uses COFF ABI (not EABI) — ASM files have COFF symbol conventions
    # Rebuild RTS archive index (needed on some cl2000 versions)
    RTS33_LIB="$BUILD_DIR/rts2800_fpu32.lib"
    if [ ! -f "$RTS33_LIB" ] || [ ! -w "$RTS33_LIB" ]; then
        rm -f "$RTS33_LIB"
        cp "$CGT_DIR/lib/rts2800_fpu32.lib" "$RTS33_LIB"
        chmod u+w "$RTS33_LIB"
        ar2000 -r "$RTS33_LIB" 2>/dev/null || true
        echo "Rebuilt COFF RTS library index"
    fi

    COMPILER33_FLAGS=(
        -v28
        --float_support=fpu32
        -ml -mt
        -O2 -g
        -I"$COMMON33_INC"
        -I"$HEADERS33_INC"
        -I"$CGT_DIR/include"
    )

    LINKER33_FLAGS=(
        -z
        --rom_model
        --entry_point=code_start
        --stack_size=0x400
        --heap_size=0x100
        -l"$RTS33_LIB"
        "$LINKER33_CMD"
        "$HEADERS33_CMD/DSP2833x_Headers_nonBIOS.cmd"
    )

    declare -A F2833X_EXAMPLES=(
        ["f2833x_led_blink"]="$DEV33/examples/timed_led_blink/Example_2833xLEDBlink.c"
        ["f2833x_cpu_timer"]="$DEV33/examples/cpu_timer/Example_2833xCpuTimer.c"
        ["f2833x_adc_soc"]="$DEV33/examples/adc_soc/Example_2833xAdcSoc.c"
        ["f2833x_gpio_setup"]="$DEV33/examples/gpio_setup/Example_2833xGpioSetup.c"
        ["f2833x_gpio_toggle"]="$DEV33/examples/gpio_toggle/Example_2833xGpioToggle.c"
        ["f2833x_sci_echoback"]="$DEV33/examples/sci_echoback/Example_2833xSci_Echoback.c"
        ["f2833x_spi_loopback"]="$DEV33/examples/spi_loopback/Example_2833xSpi_FFDLB.c"
        ["f2833x_epwm_int"]="$DEV33/examples/epwm_timer_interrupts/Example_2833xEPwmTimerInt.c"
        ["f2833x_ecap_apwm"]="$DEV33/examples/ecap_apwm/Example_2833xECap_apwm.c"
        ["f2833x_ecan"]="$DEV33/examples/ecan_back2back/Example_2833xECanBack2Back.c"
        ["f2833x_i2c"]="$DEV33/examples/i2c_eeprom/Example_2833xI2C_eeprom.c"
        ["f2833x_dma"]="$DEV33/examples/dma_ram_to_ram/Example_2833xDMA_ram_to_ram.c"
        ["f2833x_ext_int"]="$DEV33/examples/external_interrupt/Example_2833xExternalInterrupt.c"
        ["f2833x_fpu"]="$DEV33/examples/fpu_hardware/Example_2833xFPU_hardware.c"
        ["f2833x_watchdog"]="$DEV33/examples/watchdog/Example_2833xWatchdog.c"
    )

    success33=0
    fail33=0

    for name in "${!F2833X_EXAMPLES[@]}"; do
        src="${F2833X_EXAMPLES[$name]}"
        out="$BUILD_DIR/${name}.out"
        map="$BUILD_DIR/${name}.map"
        obj_dir="$BUILD_DIR/obj_${name}"

        echo -n "Building $name... "

        if [ ! -f "$src" ]; then
            echo "SKIP (source not found)"
            continue
        fi

        mkdir -p "$obj_dir"

        # Per-example extra source files (from example dir + peripheral drivers)
        EXTRA_SRCS=()
        ex_dir="$(dirname "$src")"
        for extra_c in "$ex_dir"/*.c; do
            [ "$extra_c" = "$src" ] && continue
            [ -f "$extra_c" ] && EXTRA_SRCS+=("$extra_c")
        done
        # Add peripheral-specific drivers needed by specific examples
        case "$name" in
            *sci*) [ -f "$COMMON33_SRC/DSP2833x_Sci.c" ] && EXTRA_SRCS+=("$COMMON33_SRC/DSP2833x_Sci.c") ;;
            *spi*) [ -f "$COMMON33_SRC/DSP2833x_Spi.c" ] && EXTRA_SRCS+=("$COMMON33_SRC/DSP2833x_Spi.c") ;;
            *ecan*) [ -f "$COMMON33_SRC/DSP2833x_ECan.c" ] && EXTRA_SRCS+=("$COMMON33_SRC/DSP2833x_ECan.c") ;;
            *i2c*) [ -f "$COMMON33_SRC/DSP2833x_I2C.c" ] && EXTRA_SRCS+=("$COMMON33_SRC/DSP2833x_I2C.c") ;;
            *eqep*) [ -f "$COMMON33_SRC/DSP2833x_EQep.c" ] && EXTRA_SRCS+=("$COMMON33_SRC/DSP2833x_EQep.c") ;;
        esac

        if cl2000 "${COMPILER33_FLAGS[@]}" \
            --obj_directory="$obj_dir" \
            "$src" "${EXTRA_SRCS[@]}" \
            "${SUPPORT33_SRCS[@]}" \
            "${LINKER33_FLAGS[@]}" \
            -m"$map" \
            -o"$out" 2>"$BUILD_DIR/${name}.log"; then
            echo "OK ($(wc -c < "$out") bytes)"
            success33=$((success33 + 1))
        else
            echo "FAILED"
            tail -5 "$BUILD_DIR/${name}.log"
            fail33=$((fail33 + 1))
        fi
    done

    echo
    echo "=== f2833x results: $success33 OK, $fail33 failed ==="
    success=$((success + success33))
    fail=$((fail + fail33))
fi

echo
echo "=== TOTAL: $success OK, $fail failed ==="

echo
echo "=== Output files ==="
for out in "$BUILD_DIR"/*.out; do
    [ -f "$out" ] || continue
    fmt=$(file -b "$out" | head -c 50)
    echo "  $(basename "$out"): $fmt"
done

exit $fail
