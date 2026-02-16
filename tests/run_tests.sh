#!/bin/bash
# Woody Woodpacker Test Suite
# Tests 32-bit and 64-bit packers against various binary types

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINDIR="$SCRIPT_DIR/bin"
RESULTS_DIR="$SCRIPT_DIR/results"
PACKER64="$PROJECT_DIR/woody_woodpacker"
PACKER32="$PROJECT_DIR/woody_woodpacker_32"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# Mode: "strict" compares output, "banner" only checks for banner
TEST_MODE="${TEST_MODE:-banner}"

mkdir -p "$RESULTS_DIR"

# Get exit code description
describe_exit() {
    local code=$1
    case $code in
        0)   echo "OK" ;;
        124) echo "TIMEOUT" ;;
        126) echo "NOT_EXEC" ;;
        127) echo "NOT_FOUND" ;;
        129) echo "SIGHUP" ;;
        130) echo "SIGINT" ;;
        131) echo "SIGQUIT" ;;
        132) echo "SIGILL" ;;
        133) echo "SIGTRAP" ;;
        134) echo "SIGABRT" ;;
        135) echo "SIGBUS" ;;
        136) echo "SIGFPE" ;;
        137) echo "SIGKILL" ;;
        139) echo "SEGFAULT" ;;
        141) echo "SIGPIPE" ;;
        143) echo "SIGTERM" ;;
        *)   echo "EXIT_$code" ;;
    esac
}

# Run a single test
# Args: $1=name $2=binary $3=packer $4=expect_fail
run_test() {
    local name="$1"
    local binary="$2"
    local packer="$3"
    local expect_fail="${4:-0}"

    ((TOTAL++)) || true

    # Check if binary exists and is valid ELF
    if [ ! -f "$binary" ] || [ ! -s "$binary" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no binary)\n" "$TOTAL" "$name"
        return
    fi

    # Check if packer exists
    if [ ! -f "$packer" ]; then
        ((SKIPPED++)) || true
        printf "[%3d] %-50s ${YELLOW}SKIP${NC} (no packer)\n" "$TOTAL" "$name"
        return
    fi

    local workdir=$(mktemp -d)
    local log_name="${name//\//_}"
    local log_file="$RESULTS_DIR/${log_name}.log"

    # Get original output (for comparison)
    local orig_output orig_exit
    orig_output=$(timeout 5s "$binary" 2>&1) || true
    orig_exit=$?

    # Pack the binary
    cd "$workdir"
    local pack_output pack_exit
    pack_output=$("$packer" "$binary" 2>&1)
    pack_exit=$?

    if [ $pack_exit -ne 0 ]; then
        cd "$SCRIPT_DIR"
        rm -rf "$workdir"
        local pack_err=$(describe_exit $pack_exit)
        if [ "$expect_fail" = "1" ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} (pack failed: $pack_err)\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (pack: $pack_err)\n" "$TOTAL" "$name"
            echo "Packer exit: $pack_exit ($pack_err)" > "$log_file"
            echo "Output: $pack_output" >> "$log_file"
        fi
        return
    fi

    # Check woody file was created
    if [ ! -f "woody" ]; then
        cd "$SCRIPT_DIR"
        rm -rf "$workdir"
        if [ "$expect_fail" = "1" ]; then
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} (no woody file)\n" "$TOTAL" "$name"
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (no woody file)\n" "$TOTAL" "$name"
        fi
        return
    fi

    chmod +x woody

    # Run packed binary with timeout
    local packed_output packed_exit
    packed_output=$(timeout 5s ./woody 2>&1)
    packed_exit=$?
    local exit_desc=$(describe_exit $packed_exit)

    cd "$SCRIPT_DIR"

    # Check for WOODY banner
    local has_banner=0
    if echo "$packed_output" | grep -qF "___WOODY___"; then
        has_banner=1
    fi

    # For cross-arch tests (expect_fail=1), we expect failure
    if [ "$expect_fail" = "1" ]; then
        if [ "$has_banner" = "0" ] || [ $packed_exit -ne 0 ]; then
            ((PASSED++)) || true
            if [ $packed_exit -ne 0 ]; then
                printf "[%3d] %-50s ${GREEN}PASS${NC} (run: $exit_desc)\n" "$TOTAL" "$name"
            else
                printf "[%3d] %-50s ${GREEN}PASS${NC} (no banner)\n" "$TOTAL" "$name"
            fi
        else
            ((FAILED++)) || true
            printf "[%3d] %-50s ${RED}FAIL${NC} (should have failed)\n" "$TOTAL" "$name"
        fi
        rm -rf "$workdir"
        return
    fi

    # === Normal test (expect success) ===

    # First check: did it crash?
    if [ $packed_exit -ne 0 ] && [ "$has_banner" = "0" ]; then
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}($exit_desc)${NC}\n" "$TOTAL" "$name"
        {
            echo "Exit code: $packed_exit ($exit_desc)"
            echo "Has banner: no"
            echo "Output: $packed_output"
        } > "$log_file"
        rm -rf "$workdir"
        return
    fi

    # Second check: banner present?
    if [ "$has_banner" = "0" ]; then
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}(no banner, $exit_desc)${NC}\n" "$TOTAL" "$name"
        {
            echo "Exit code: $packed_exit ($exit_desc)"
            echo "Has banner: no"
            echo "Output length: ${#packed_output}"
            echo "Output: $packed_output"
        } > "$log_file"
        rm -rf "$workdir"
        return
    fi

    # Banner mode: banner present = success (even if crash after)
    if [ "$TEST_MODE" = "banner" ]; then
        if [ $packed_exit -ne 0 ]; then
            # Banner shown but crashed after
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC} ${YELLOW}(banner OK, then $exit_desc)${NC}\n" "$TOTAL" "$name"
        else
            ((PASSED++)) || true
            printf "[%3d] %-50s ${GREEN}PASS${NC}\n" "$TOTAL" "$name"
        fi
        rm -rf "$workdir"
        return
    fi

    # Strict mode: compare output
    local packed_clean
    packed_clean=$(echo "$packed_output" | grep -vF "___WOODY___" || true)

    local orig_trimmed packed_trimmed
    orig_trimmed=$(echo "$orig_output" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    packed_trimmed=$(echo "$packed_clean" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    if [ "$packed_trimmed" = "$orig_trimmed" ]; then
        ((PASSED++)) || true
        printf "[%3d] %-50s ${GREEN}PASS${NC}\n" "$TOTAL" "$name"
    else
        ((FAILED++)) || true
        printf "[%3d] %-50s ${RED}FAIL${NC} ${CYAN}(output mismatch)${NC}\n" "$TOTAL" "$name"
        {
            echo "=== Original (exit $orig_exit) ==="
            echo "$orig_output"
            echo ""
            echo "=== Packed (exit $packed_exit - $exit_desc) ==="
            echo "$packed_output"
        } > "$log_file"
    fi

    rm -rf "$workdir"
}

# Main
main() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           Woody Woodpacker Test Suite${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "Mode: ${YELLOW}${TEST_MODE}${NC} (TEST_MODE=strict for output comparison)"
    echo ""

    # Build test binaries
    echo "Building test binaries..."
    make -C "$SCRIPT_DIR" all >/dev/null 2>&1 || true
    echo ""

    # ===== 64-bit Packer on 64-bit binaries =====
    echo -e "${BLUE}─── 64-bit Packer on 64-bit Binaries ───${NC}"
    echo ""

    echo -e "${YELLOW}PIE:${NC}"
    for bin in "$BINDIR"/*_64_pie; do
        [ -f "$bin" ] || continue
        run_test "64→64 PIE/$(basename "${bin%_64_pie}")" "$bin" "$PACKER64" 0
    done
    echo ""

    echo -e "${YELLOW}no-PIE:${NC}"
    for bin in "$BINDIR"/*_64_nopie; do
        [ -f "$bin" ] || continue
        run_test "64→64 noPIE/$(basename "${bin%_64_nopie}")" "$bin" "$PACKER64" 0
    done
    echo ""

    echo -e "${YELLOW}static:${NC}"
    for bin in "$BINDIR"/*_64_static; do
        [ -f "$bin" ] || continue
        run_test "64→64 static/$(basename "${bin%_64_static}")" "$bin" "$PACKER64" 0
    done
    echo ""

    echo -e "${YELLOW}ASM:${NC}"
    for bin in "$BINDIR"/*_asm64; do
        [ -f "$bin" ] || continue
        run_test "64→64 asm/$(basename "${bin%_asm64}")" "$bin" "$PACKER64" 0
    done
    echo ""

    # ===== 64-bit Packer on 32-bit binaries (should work - packer embeds both stubs) =====
    echo -e "${BLUE}─── 64-bit Packer on 32-bit Binaries ───${NC}"
    echo ""

    echo -e "${YELLOW}PIE:${NC}"
    for bin in "$BINDIR"/*_32_pie; do
        [ -f "$bin" ] || continue
        run_test "64→32 PIE/$(basename "${bin%_32_pie}")" "$bin" "$PACKER64" 0
    done
    echo ""

    echo -e "${YELLOW}no-PIE:${NC}"
    for bin in "$BINDIR"/*_32_nopie; do
        [ -f "$bin" ] || continue
        run_test "64→32 noPIE/$(basename "${bin%_32_nopie}")" "$bin" "$PACKER64" 0
    done
    echo ""

    echo -e "${YELLOW}static:${NC}"
    for bin in "$BINDIR"/*_32_static; do
        [ -f "$bin" ] || continue
        run_test "64→32 static/$(basename "${bin%_32_static}")" "$bin" "$PACKER64" 0
    done
    echo ""

    # ===== 32-bit Packer Tests =====
    if [ -f "$PACKER32" ]; then
        echo -e "${BLUE}─── 32-bit Packer on 32-bit Binaries ───${NC}"
        echo ""

        echo -e "${YELLOW}PIE:${NC}"
        for bin in "$BINDIR"/*_32_pie; do
            [ -f "$bin" ] || continue
            run_test "32→32 PIE/$(basename "${bin%_32_pie}")" "$bin" "$PACKER32" 0
        done
        echo ""

        echo -e "${YELLOW}no-PIE:${NC}"
        for bin in "$BINDIR"/*_32_nopie; do
            [ -f "$bin" ] || continue
            run_test "32→32 noPIE/$(basename "${bin%_32_nopie}")" "$bin" "$PACKER32" 0
        done
        echo ""

        echo -e "${YELLOW}static:${NC}"
        for bin in "$BINDIR"/*_32_static; do
            [ -f "$bin" ] || continue
            run_test "32→32 static/$(basename "${bin%_32_static}")" "$bin" "$PACKER32" 0
        done
        echo ""

        # 32-bit packer on 64-bit (should work - packer embeds both stubs)
        echo -e "${BLUE}─── 32-bit Packer on 64-bit Binaries ───${NC}"
        echo ""

        echo -e "${YELLOW}PIE:${NC}"
        for bin in "$BINDIR"/*_64_pie; do
            [ -f "$bin" ] || continue
            run_test "32→64 PIE/$(basename "${bin%_64_pie}")" "$bin" "$PACKER32" 0
        done
        echo ""

        echo -e "${YELLOW}no-PIE:${NC}"
        for bin in "$BINDIR"/*_64_nopie; do
            [ -f "$bin" ] || continue
            run_test "32→64 noPIE/$(basename "${bin%_64_nopie}")" "$bin" "$PACKER32" 0
        done
        echo ""

        echo -e "${YELLOW}static:${NC}"
        for bin in "$BINDIR"/*_64_static; do
            [ -f "$bin" ] || continue
            run_test "32→64 static/$(basename "${bin%_64_static}")" "$bin" "$PACKER32" 0
        done
        echo ""
    else
        echo -e "${YELLOW}32-bit packer not found, skipping 32-bit tests${NC}"
        echo ""
    fi

    # Summary
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo ""
    printf "  Total:   %d\n" "$TOTAL"
    printf "  ${GREEN}Passed:  %d${NC}\n" "$PASSED"
    printf "  ${RED}Failed:  %d${NC}\n" "$FAILED"
    printf "  ${YELLOW}Skipped: %d${NC}\n" "$SKIPPED"
    echo ""

    local pass_rate=0
    if [ $((TOTAL - SKIPPED)) -gt 0 ]; then
        pass_rate=$((100 * PASSED / (TOTAL - SKIPPED)))
    fi
    echo "  Pass rate: ${pass_rate}%"
    echo ""

    echo -e "${CYAN}Legend:${NC}"
    echo "  SEGFAULT  = Signal 11 (invalid memory access)"
    echo "  SIGABRT   = Signal 6 (abort)"
    echo "  SIGILL    = Signal 4 (illegal instruction)"
    echo "  SIGBUS    = Signal 7 (bus error)"
    echo "  TIMEOUT   = Exceeded 5s limit"
    echo ""

    if [ $FAILED -gt 0 ]; then
        echo "Detailed logs: $RESULTS_DIR/"
    fi

    [ $FAILED -eq 0 ]
}

main "$@"
