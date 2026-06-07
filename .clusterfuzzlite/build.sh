#!/bin/bash -eu

# 'pip install .' installs agent-guardian from local source and cannot be
# hash-pinned from PyPI (it is not a PyPI distribution).
# The Scorecard PinnedDependenciesID alert for this line must be dismissed
# in GitHub Security as a local-source install, not a PyPI fetch.
python3 -m pip install .

for fuzzer in "$SRC"/agent-guardian/fuzzers/*_fuzzer.py; do
  target="$(basename "$fuzzer" .py)"
  fuzzer_package="${target}.pkg"
  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"
  cp "$fuzzer" "$OUT/${target}.py"
  cat > "$OUT/$target" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
exec "\$this_dir/${fuzzer_package}" "\$@"
EOF
  chmod +x "$OUT/$target"
done
