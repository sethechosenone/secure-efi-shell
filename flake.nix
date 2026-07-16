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

        # The released auth-gated Shell.efi, fetched from the GitHub release
        # (building EDK2 inside a derivation is not worth the weight).
        # Bump url and hash together when cutting a new release.
        shell-efi = pkgs.stdenv.mkDerivation {
          pname = "secure-efi-shell";
          version = "0.1.0";

          src = pkgs.fetchurl {
            url = "https://github.com/sethechosenone/secure-efi-shell/releases/download/v0.1.0/Shell.efi";
            hash = "sha256-1xbBJupfi+ySvuaTVi7gBdlAsKKy9knieb2hi3Obc2M=";
          };

          dontUnpack = true;

          installPhase = ''
            mkdir -p $out
            cp $src $out/shell.efi
          '';

          meta = with pkgs.lib; {
            description = "Auth-gated EDK2 UEFI shell — password gate backed by TPM2 PolicyPCR(7)";
            platforms = platforms.linux;
          };
        };

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
          # Pipe via stdin so the password never appears in /proc/*/cmdline
          printf '%s\n' "$GATE_PASS" | ${pkgs.python3}/bin/python3 gen-digest.py \
            --output tpmstate/expected.bin
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
        packages = {
          default = shell-efi;
          secure-efi-shell = shell-efi;
        };

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
      }) // {
      # Turnkey integration for Limine + sbctl systems:
      #   boot.secure-efi-shell.enable = true;
      # Stages the shell on the ESP via boot.loader.limine.additionalFiles and
      # re-signs it with the device's own sbctl keys during activation. The
      # Limine installer re-copies the unsigned binary on every rebuild, but
      # activation runs after the bootloader install on `nixos-rebuild switch`,
      # so the ESP copy always ends up signed. Keys never leave /var/lib/sbctl.
      #
      # Caveat: with `nixos-rebuild boot`, activation only runs once the new
      # generation boots — selecting the shell entry on that very first reboot
      # (before Linux has run) finds it unsigned and Secure Boot rejects it.
      # Booting Linux once fixes it.
      nixosModules.secure-efi-shell = { config, lib, pkgs, ... }:
        let
          cfg = config.boot.secure-efi-shell;
          shell-efi = self.packages.${pkgs.stdenv.hostPlatform.system}.secure-efi-shell;
          espShell = "${config.boot.loader.efi.efiSysMountPoint}/limine/efi/shell/shell.efi";

          # One-time per-device TPM ceremony: seals the stretched password hash
          # into NV 0x01800001 behind PolicyPCR(7), using the REAL TPM via the
          # kernel resource manager. PCR 7 is read from the running system —
          # both Linux and the shell chainload verify against the same db key,
          # so the boot-menu PCR 7 matches what we capture here.
          # gen-digest.py comes from this flake's source, so the KDF parameters
          # can never drift from the gate that checks them.
          provision-efi-shell = pkgs.writeShellScriptBin "provision-efi-shell" ''
            set -e
            NVINDEX=0x01800001
            if [ "$(id -u)" -ne 0 ]; then
              echo "must run as root (TPM owner auth + /dev/tpmrm0)"; exit 1
            fi

            WORK="$(mktemp -d)"
            trap 'rm -rf "$WORK"' EXIT

            echo "reading PCR 7 from /dev/tpmrm0..."
            ${pkgs.tpm2-tools}/bin/tpm2_pcrread sha256:7 -o "$WORK/pcr7.bin" >/dev/null

            # Compute the PolicyPCR(sha256:7) digest directly from the TPM spec.
            ${pkgs.python3}/bin/python3 - "$WORK/pcr7.bin" "$WORK/policy.digest" <<'PYEOF'
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

            IFS= read -r -s -p "gate password: " GATE_PASS; echo ""
            IFS= read -r -s -p "confirm: "       GATE_CONF; echo ""
            if [ "$GATE_PASS" != "$GATE_CONF" ]; then
              echo "passwords do not match"; exit 1
            fi
            echo "stretching (100k rounds)..."
            # Pipe via stdin so the password never appears in /proc/*/cmdline
            printf '%s\n' "$GATE_PASS" | ${pkgs.python3}/bin/python3 ${self}/gen-digest.py \
              --output "$WORK/expected.bin"
            unset GATE_PASS GATE_CONF

            # (Re)define the NV index with the PCR policy as read authorization.
            ${pkgs.tpm2-tools}/bin/tpm2_nvundefine -C o "$NVINDEX" 2>/dev/null || true
            ${pkgs.tpm2-tools}/bin/tpm2_nvdefine "$NVINDEX" -C o -s 32 \
              -a "ownerwrite|policyread" \
              -L "$WORK/policy.digest"
            ${pkgs.tpm2-tools}/bin/tpm2_nvwrite "$NVINDEX" -C o -i "$WORK/expected.bin"
            echo "NV $NVINDEX provisioned — reboot and test the Secure Shell entry"
          '';
        in
        {
          options.boot.secure-efi-shell = {
            enable = lib.mkEnableOption "the auth-gated UEFI shell in the Limine boot menu";

            addBootEntry = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Add a Limine menu entry for the shell. Disable to write your own
                entry (image_path: boot():/limine/efi/shell/shell.efi).
              '';
            };

            autoSign = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Re-sign the ESP copy with this device's sbctl keys at activation.
                Without this the entry stops verifying after every rebuild.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ provision-efi-shell ];

            boot.loader.limine = {
              additionalFiles."efi/shell/shell.efi" = "${shell-efi}/shell.efi";
              extraEntries = lib.mkIf cfg.addBootEntry ''
                /UEFI Shell
                protocol: efi
                comment: Command-line shell for running UEFI programs (requires secure boot)
                image_path: boot():/limine/efi/shell/shell.efi
              '';
            };

            system.activationScripts.secure-efi-shell-sign = lib.mkIf cfg.autoSign ''
              if [ -f "${espShell}" ] && [ -d /var/lib/sbctl/keys ]; then
                ${pkgs.sbctl}/bin/sbctl sign "${espShell}" \
                  || echo "[secure-efi-shell] warning: signing failed; boot entry will not verify" >&2
              fi
            '';
          };
        };
    };
}
