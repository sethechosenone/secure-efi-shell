{
  description = "Dev environment for secure-efi-shell (EDK2 ShellPkg fork)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Boot the fake ESP (./esp) in QEMU with OVMF; exit with Ctrl-A x
        # OVMFFull (not OVMF) so the firmware has the TCG2/TPM2 driver stack;
        # swtpm provides a software TPM2 whose state persists in ./tpmstate.
        # swtpm exposes BOTH a ctrl socket (for QEMU) AND a TCP server (port 2321,
        # for tpm2-tools) so capture-pcr7 can read PCR 7 while QEMU is running.
        # The ctrl socket lives OUTSIDE the tree: a leftover socket file inside a
        # non-git flake dir breaks `nix develop` (path inputs can't copy sockets).
        run-qemu = pkgs.writeShellScriptBin "run-qemu" ''
          SOCKDIR="''${XDG_RUNTIME_DIR:-/tmp}/secure-efi-shell"
          mkdir -p tpmstate "$SOCKDIR"
          ${pkgs.swtpm}/bin/swtpm socket --tpm2 --tpmstate dir=tpmstate \
            --ctrl type=unixio,path="$SOCKDIR/ctrl.sock" \
            --flags not-need-init,startup-clear --terminate --daemon
          exec ${pkgs.qemu}/bin/qemu-system-x86_64 -machine q35 -m 512 \
            -drive if=pflash,format=raw,readonly=on,file=${pkgs.OVMFFull.fd}/FV/OVMF_CODE.fd \
            -drive if=pflash,format=raw,snapshot=on,file=${pkgs.OVMFFull.fd}/FV/OVMF_VARS.fd \
            -chardev socket,id=chrtpm,path="$SOCKDIR/ctrl.sock" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-tis,tpmdev=tpm0 \
            -drive format=raw,file=fat:rw:esp \
            -nographic "$@"
        '';

        # Convert the PCR 7 hex string printed by the gate's debug output into
        # tpmstate/pcr7.bin (32 bytes) for use by provision-swtpm.
        # Usage: capture-pcr7 <64-char hex string>
        # Example: capture-pcr7 3a4b5c...
        capture-pcr7 = pkgs.writeShellScriptBin "capture-pcr7" ''
          set -e
          if [ -z "$1" ] || [ ''${#1} -ne 64 ]; then
            echo "usage: capture-pcr7 <64-char hex string from gate debug output>"
            exit 1
          fi
          printf '%b' "$(echo "$1" | sed 's/../\\x&/g')" > tpmstate/pcr7.bin
          echo "wrote tpmstate/pcr7.bin (32 bytes)"
        '';

        # Provision the expected-hash NV index into the swtpm state that run-qemu boots.
        # Run AFTER capture-pcr7 (needs tpmstate/pcr7.bin) and AFTER QEMU is shut
        # down (swtpm locks the state dir).  Creates a PolicyPCR(7) policy so the
        # TPM only releases the expected hash when PCR 7 matches the captured boot value.
        # Prompts for the gate password; writes the stretched hash to NV 0x01800001.
        provision-swtpm = pkgs.writeShellScriptBin "provision-swtpm" ''
          set -e
          NVINDEX=0x01800001
          mkdir -p tpmstate
          if [ ! -f tpmstate/pcr7.bin ]; then
            echo "tpmstate/pcr7.bin not found — run capture-pcr7 while QEMU is up first"
            exit 1
          fi
          ${pkgs.swtpm}/bin/swtpm socket --tpm2 --tpmstate dir=tpmstate \
            --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
            --flags not-need-init,startup-clear \
            --pid file=tpmstate/provision.pid --daemon
          trap 'kill "$(cat tpmstate/provision.pid)" 2>/dev/null || true' EXIT
          sleep 0.3
          export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=2321"

          # Compute the PolicyPCR(sha256:7) digest directly from the TPM spec.
          ${pkgs.python3}/bin/python3 - tpmstate/pcr7.bin tpmstate/policy.digest <<'PYEOF'
import sys, hashlib, struct
pcr7 = open(sys.argv[1], 'rb').read()
assert len(pcr7) == 32, f"pcr7.bin must be 32 bytes, got {len(pcr7)}"
pcr_sel = (struct.pack('>I', 1) +       # TPML_PCR_SELECTION count=1
           struct.pack('>H', 0x000B) +  # TPM_ALG_SHA256
           bytes([3, 0x80, 0x00, 0x00]))# sizeofSelect=3, PCR 7 bit set
policy = hashlib.sha256(
    bytes(32) + struct.pack('>I', 0x0000017F) + pcr_sel +
    hashlib.sha256(pcr7).digest()
).digest()
open(sys.argv[2], 'wb').write(policy)
print(f"policy digest: {policy.hex()}")
PYEOF

          # Prompt for the gate password and compute the expected hash.
          IFS= read -r -s -p "gate password: " GATE_PASS; echo ""
          IFS= read -r -s -p "confirm: "       GATE_CONF; echo ""
          if [ "$GATE_PASS" != "$GATE_CONF" ]; then
            echo "passwords do not match"; exit 1
          fi
          ${pkgs.python3}/bin/python3 gen-digest.py \
            --output tpmstate/expected.bin "$GATE_PASS"
          unset GATE_PASS GATE_CONF

          # (Re)define the NV index with the PCR policy as its read authorization.
          ${pkgs.tpm2-tools}/bin/tpm2_nvundefine -C o "$NVINDEX" 2>/dev/null || true
          ${pkgs.tpm2-tools}/bin/tpm2_nvdefine "$NVINDEX" -C o -s 32 \
            -a "ownerwrite|policyread" \
            -L tpmstate/policy.digest
          ${pkgs.tpm2-tools}/bin/tpm2_nvwrite "$NVINDEX" -C o -i tpmstate/expected.bin
          echo "NV $NVINDEX provisioned with PolicyPCR(7) — expected hash sealed to PCR 7"
        '';

        # Clone tianocore/edk2 at the pinned commit and apply our overlay.
        # Safe to re-run: skips clone if edk2/ already exists.
        setup-edk2 = pkgs.writeShellScriptBin "setup-edk2" ''
          set -e
          EDK2_COMMIT="6a6ec8a228b6dd99f9a52a78c2a4c82be9b73ec8"
          if [ -d edk2/.git ]; then
            echo "edk2/ already present — skipping clone"
          else
            echo "cloning tianocore/edk2 (blobless, ~fast)..."
            git clone --filter=blob:none --no-checkout \
              https://github.com/tianocore/edk2.git edk2
            git -C edk2 checkout "$EDK2_COMMIT"
            echo "initialising required submodules..."
            git -C edk2 submodule update --init --recursive
          fi
          echo "applying overlay..."
          cp -r overlay/* edk2/
          echo "done — run build-shell to compile"
        '';

        # Build ShellPkg under bear (keeps compile_commands.json fresh for clangd);
        # self-contained: sources edksetup.sh itself, so it works in any shell
        build-shell = pkgs.writeShellScriptBin "build-shell" ''
          set -e
          cd "''${EDK2_ROOT:-$PWD/edk2}"
          source ./edksetup.sh >/dev/null
          exec ${pkgs.bear}/bin/bear --append -- build -a X64 -t GCC -p ShellPkg/ShellPkg.dsc "$@"
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          # EDK2 BaseTools won't compile with Nix's default fortify/format hardening
          hardeningDisable = [ "format" "fortify" ];

          nativeBuildInputs = with pkgs; [
            # EDK2 build requirements
            gcc
            gnumake
            nasm
            acpica-tools # iasl
            python3
            libuuid # uuid headers for BaseTools
            # Editor tooling
            clang-tools # clangd LSP
            gdb # debugger; attach to QEMU's gdbstub with `target remote :1234`
            bear # wrap the edk2 build to generate compile_commands.json for clangd
            # Test loop
            qemu
            swtpm # software TPM2 for QEMU
            tpm2-tools # inspect/provision TPM from the host side
            run-qemu
            capture-pcr7
            build-shell
            provision-swtpm
            setup-edk2
          ];

          # OVMF firmware for QEMU (OVMF_CODE.fd / OVMF_VARS.fd live here)
          OVMF_FV = "${pkgs.OVMFFull.fd}/FV";

          shellHook = ''
            export EDK2_ROOT="$PWD/edk2"
            # Put EDK2's `build` wrapper on PATH for interactive use;
            # edksetup.sh derives WORKSPACE from cwd, so hop in and back
            if [ -f "$EDK2_ROOT/edksetup.sh" ]; then
              pushd "$EDK2_ROOT" >/dev/null
              source ./edksetup.sh >/dev/null
              popd >/dev/null
            fi
            echo "EDK2 dev shell — OVMF firmware in $OVMF_FV"
          '';
        };
      });
}
