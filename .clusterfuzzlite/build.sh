#!/bin/bash -eu

python3 -m pip install --upgrade pip
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
