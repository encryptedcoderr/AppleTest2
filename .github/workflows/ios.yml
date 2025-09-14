name: iOS JPEG Fuzzer Workflow

on:
  # This allows you to run the workflow manually from the Actions tab in GitHub
  workflow_dispatch:

jobs:
  fuzz-and-log-ios:
    name: Generate Malicious JPEG and Log Simulator Response
    # This must run on a macOS runner to get access to Xcode and the iOS Simulator
    runs-on: macos-latest

    steps:
      - name: 1. Checkout Repository
        uses: actions/checkout@v4
        with:
          # This ensures your Python script is available to the workflow
          path: main

      - name: 2. Set up Python Environment
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: 3. Install Python Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install Pillow

      - name: 4. Generate Malicious JPEGs
        id: generate_jpegs
        working-directory: ./main
        run: |
          # Run your script to create the JPEGs in its output directory
          python MaliciousJPEGGenerator.py
          
          # List all generated JPEGs for individual opening
          JPEGS=$(ls malicious_jpegs/exploit_*.jpg | tr '\n' ' ')
          echo "jpeg_list=${JPEGS}" >> "$GITHUB_OUTPUT"
          echo "output_dir=malicious_jpegs" >> "$GITHUB_OUTPUT"

      - name: 5. Fuzz Simulator and Capture Log
        id: fuzz_ios
        working-directory: ./main
        run: |
          set -euo pipefail  # Strict error handling
          JPEG_LIST="${{ steps.generate_jpegs.outputs.jpeg_list }}"
          LOG_FILE="ios_simulator_errors.log"
          NDJSON_FILE="ios_simulator_ndjson.log"
          INSTR_TRACE="allocations.trace"

          # Install dependencies
          brew install coreutils jq

          echo "--- Finding an available iPhone simulator (iOS 18+) ---"
          SIMULATOR_UDID=$(xcrun simctl list devices available -j | jq -r '.devices | .[] | .[] | select(.isAvailable == true and (.name? | startswith("iPhone") // false) and (.runtime? | contains("iOS-18") // false)) | .udid' | head -n 1)
          
          if [ -z "$SIMULATOR_UDID" ]; then
            echo "--- No iOS 18+ available; fallback to latest iPhone ---"
            SIMULATOR_UDID=$(xcrun simctl list devices available -j | jq -r '.devices | .[] | .[] | select(.isAvailable == true and (.name? | startswith("iPhone") // false)) | .udid' | head -n 1)
            if [ -z "$SIMULATOR_UDID" ]; then
              echo "::error::No iPhone simulators found."
              exit 1
            fi
            xcrun simctl boot "${SIMULATOR_UDID}"
            # Extended boot poll
            BOOT_TIMEOUT=180
            BOOT_ELAPSED=0
            while [ $BOOT_ELAPSED -lt $BOOT_TIMEOUT ]; do
              BOOT_STATUS=$(xcrun simctl bootstatus "${SIMULATOR_UDID}" | grep -E "(Status|Finished)")
              if echo "$BOOT_STATUS" | grep -q "Finished"; then
                echo "--- Boot complete! ---"
                break
              fi
              sleep 5
              BOOT_ELAPSED=$((BOOT_ELAPSED + 5))
            done
          else
            xcrun simctl bootstatus "${SIMULATOR_UDID}" -b
            sleep 10
          fi
          echo "Using UDID: ${SIMULATOR_UDID}"

          # Upload JPEGs and track DCIM paths
          echo "--- Uploading JPEGs and noting DCIM paths ---"
          DCIM_PATHS=""
          for jpeg in $JPEG_LIST; do
            if xcrun simctl addmedia "${SIMULATOR_UDID}" "$jpeg" >> /dev/null 2>&1; then
              echo "Uploaded: $jpeg"
              # Post-upload DCIM path (approx; actual IMG_XXXX.JPG)
              DCIM_PATH="/var/mobile/Media/DCIM/100APPLE/$(basename $jpeg)"
              DCIM_PATHS="${DCIM_PATHS} $DCIM_PATH"
            else
              echo "Upload skipped for $jpeg"
            fi
          done
          echo "DCIM paths: $DCIM_PATHS"

          echo "--- Starting Instruments trace for allocations (OOM detection) ---"
          xcrun xctrace run "${SIMULATOR_UDID}" --template "Allocations" --attachments "${INSTR_TRACE}" --launchApp com.apple.mobileslideshow &
          INSTR_PID=$!

          echo "--- Starting system log capture (enhanced for ImageIO faults/crashes) ---"
          # Enhanced predicate: ImageIO, faults, crashes, specific errors
          PREDICATE='subsystem == "com.apple.photos" OR subsystem == "com.apple.imageio" OR process == "MobileSlideShow" OR messageType == fault OR messageType == error OR eventMessage CONTAINS "JPEG" OR eventMessage CONTAINS "decode" OR eventMessage CONTAINS "ImageIO" OR eventMessage CONTAINS "EXC" OR eventMessage CONTAINS "SEGV" OR eventMessage CONTAINS "Tungsten"'
          gtimeout 180s xcrun simctl spawn "${SIMULATOR_UDID}" log stream --info --debug --fault --style ndjson --predicate "$PREDICATE" > "$NDJSON_FILE" &
          LOG_PID=$!
          
          sleep 5

          echo "--- Launching Photos app ---"
          xcrun simctl launch "${SIMULATOR_UDID}" com.apple.mobileslideshow
          sleep 10

          echo "--- Triggering decode: Recents URL + fallback direct open ---"
          NUM_JPEGS=$(echo $JPEG_LIST | wc -w)
          PROCESS_DELAY=$((NUM_JPEGS * 10 + 60))  # 10s per JPEG + buffer
          xcrun simctl openurl "${SIMULATOR_UDID}" "photos-redirect://" || echo "URL fallback to app load"
          # Fallback: Direct open via spawn (forces decode)
          for dcim in $DCIM_PATHS; do
            xcrun simctl spawn "${SIMULATOR_UDID}" open "$dcim" || echo "Direct open skipped for $dcim"
            sleep 10  # Per-file decode time
          done
          sleep $PROCESS_DELAY

          echo "--- Additional buffer for async faults ---"
          sleep 60

          echo "--- Stopping log/trace capture ---"
          kill "$LOG_PID" "$INSTR_PID" 2>/dev/null || true

          echo "--- Shutting down simulator ---"
          xcrun simctl shutdown "${SIMULATOR_UDID}"

          echo "--- Log capture complete. NDJSON content: ---"
          cat "$NDJSON_FILE"
          # Fallback if empty: Extended log show for faults
          if [ ! -s "$NDJSON_FILE" ]; then
            echo "--- No stream logs; fallback search (20m) ---"
            log show --predicate 'eventMessage CONTAINS "JPEG" OR eventMessage CONTAINS "Photos" OR eventMessage CONTAINS "ImageIO" OR eventMessage CONTAINS "decode" OR eventMessage CONTAINS "MobileSlideShow" OR messageType == fault OR messageType == error OR eventMessage CONTAINS "Tungsten" OR eventMessage CONTAINS "EXC"' --last 20m --info --debug --fault --style syslog | head -200
          fi
          
          # Check for crashes
          if log show --predicate 'messageType == fault' --last 20m | grep -q "fault"; then
            echo "::warning::Potential crash detected in faults!"
          fi
          
          # Outputs
          echo "log_path=${LOG_FILE}" >> "$GITHUB_OUTPUT"
          echo "ndjson_path=${NDJSON_FILE}" >> "$GITHUB_OUTPUT"
          echo "instr_path=${INSTR_TRACE}" >> "$GITHUB_OUTPUT"
          echo "jpeg_dir=${{ steps.generate_jpegs.outputs.output_dir }}" >> "$GITHUB_OUTPUT"
          echo "dcim_paths=${DCIM_PATHS}" >> "$GITHUB_OUTPUT"

      - name: 6. Upload Fuzzing Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ios-fuzzing-results-${{ github.run_id }}
          path: |
            main/${{ steps.fuzz_ios.outputs.jpeg_dir }}
            main/${{ steps.fuzz_ios.outputs.log_path }}
            main/${{ steps.fuzz_ios.outputs.ndjson_path }}
            main/${{ steps.fuzz_ios.outputs.instr_path }}
