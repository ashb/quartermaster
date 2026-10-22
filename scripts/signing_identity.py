# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

import argparse
import base64
import hashlib
import re
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SigningIdentity:
    team: str
    certificate_sha256: str
    certificate_sha1: str


def resolve_development_identity(repository: Path, team: str | None = None) -> SigningIdentity:
    settings = repository / "signing.local.toml"
    try:
        with settings.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValueError("Signed builds require valid signing.local.toml settings at the repository root") from error
    development = document.get("development")
    if not isinstance(development, dict) or set(development) != {"team", "certificate_sha256"}:
        raise ValueError("Local development signing requires team and certificate_sha256")
    selected_team = development["team"]
    fingerprint = development["certificate_sha256"]
    if not isinstance(selected_team, str) or re.fullmatch(r"[A-Z0-9]{10}", selected_team) is None:
        raise ValueError("Local signing team must be a ten-character Apple Team ID")
    if not isinstance(fingerprint, str) or re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint) is None:
        raise ValueError("Local signing certificate_sha256 must contain 64 hexadecimal characters")
    if team is not None and team != selected_team:
        raise ValueError("Requested team differs from local development signing settings")
    certificates = subprocess.run(
        ["/usr/bin/security", "find-certificate", "-a", "-p"],
        capture_output=True, text=True, check=True, timeout=15,
    )
    matching = set()
    for pem in re.findall(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", certificates.stdout, re.DOTALL):
        der = base64.b64decode("".join(pem.split()), validate=True)
        if hashlib.sha256(der).hexdigest().upper() == fingerprint.upper():
            matching.add(hashlib.sha1(der).hexdigest().upper())
    if len(matching) != 1:
        raise ValueError("The configured development certificate was not found in the keychain search list")
    sha1 = matching.pop()
    identities = subprocess.run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
        capture_output=True, text=True, check=True, timeout=15,
    )
    available = re.findall(r'^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"', identities.stdout, re.MULTILINE)
    if sha1 not in {value.upper() for value in available}:
        raise ValueError("The configured certificate has no available valid code-signing identity")
    return SigningIdentity(selected_team, fingerprint.upper(), sha1)


def verify_bundle_certificate(bundle: Path, certificate_sha256: str) -> None:
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(bundle)],
        capture_output=True, text=True, check=True, timeout=15,
    )
    with tempfile.TemporaryDirectory(prefix="qm-signing-certificate-") as temporary:
        prefix = Path(temporary) / "certificate"
        subprocess.run(
            ["/usr/bin/codesign", "--display", f"--extract-certificates={prefix}", str(bundle)],
            capture_output=True, text=True, check=True, timeout=15,
        )
        if hashlib.sha256(prefix.with_name("certificate0").read_bytes()).hexdigest().upper() != certificate_sha256:
            raise ValueError("The built app was signed with a different certificate than the local development selection")


def main() -> None:
    parser = argparse.ArgumentParser(description="Select and verify the locally configured development signer.")
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser("select")
    select.add_argument("--team", help="Optional assertion of the configured Team ID")
    verify = commands.add_parser("verify")
    verify.add_argument("certificate_sha256")
    verify.add_argument("bundles", type=Path, nargs="+")
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "select":
            identity = resolve_development_identity(repository, arguments.team)
            print(identity.team, identity.certificate_sha1, identity.certificate_sha256)
        else:
            fingerprint = arguments.certificate_sha256
            if re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint) is None:
                raise ValueError("Expected certificate SHA-256 must contain 64 hexadecimal characters")
            for bundle in arguments.bundles:
                verify_bundle_certificate(bundle, fingerprint.upper())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
