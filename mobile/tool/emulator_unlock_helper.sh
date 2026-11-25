#!/usr/bin/env bash
# TEST ONLY helper for on-device tests on the Android EMULATOR.
#
# V18 asks for the phone's unlock before every signature, through Android's
# own BiometricPrompt. An automated test cannot tap that system screen, so
# while the tests run this script watches the emulator and types the
# emulator's TEST screen-lock PIN whenever Android's unlock screen has focus.
# Never use it with a real phone or a real PIN.
#
#   bash tool/emulator_unlock_helper.sh [PIN] [SECONDS]
# Set the emulator's TEST PIN once with:  adb shell locksettings set-pin 1234
PIN="${1:-1234}"
SECONDS_TO_RUN="${2:-3600}"
ADB="${ADB:-/c/Android/sdk/platform-tools/adb.exe}"
export MSYS_NO_PATHCONV=1
end=$(( $(date +%s) + SECONDS_TO_RUN ))
typed=0
while [ "$(date +%s)" -lt "$end" ]; do
  focus=$("$ADB" shell dumpsys window 2>/dev/null | grep -m1 "mCurrentFocus" || true)
  case "$focus" in
    *BiometricPrompt*|*ConfirmDeviceCredential*|*AuthContainer*)
      sleep 1
      "$ADB" shell input text "$PIN" >/dev/null 2>&1
      "$ADB" shell input keyevent 66 >/dev/null 2>&1
      typed=$((typed + 1))
      echo "$(date +%H:%M:%S) typed the TEST PIN ($typed) [$focus]"
      sleep 3
      ;;
  esac
  sleep 1
done
