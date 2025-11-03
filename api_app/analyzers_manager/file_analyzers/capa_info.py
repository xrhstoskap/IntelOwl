# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import os
import shutil
import subprocess
from shlex import quote
from zipfile import ZipFile

import requests
from django.conf import settings
from django.utils import timezone

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerRulesFileVersion, PythonModule
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)

BASE_LOCATION = f"{settings.MEDIA_ROOT}/capa"
RULES_LOCATION = f"{BASE_LOCATION}/capa-rules"
SIGNATURE_LOCATION = f"{BASE_LOCATION}/sigs"
RULES_FILE = f"{RULES_LOCATION}/capa_rules.zip"
RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/"


class CapaInfo(FileAnalyzer):
    shellcode: bool
    arch: str
    timeout: float = 15
    force_pull_signatures: bool = False

    def _check_if_latest_version(self, latest_version: str) -> bool:

        analyzer_rules_file_version = AnalyzerRulesFileVersion.objects.filter(
            python_module=self.python_module
        ).first()

        if analyzer_rules_file_version is None:
            return False

        return latest_version == analyzer_rules_file_version.last_downloaded_version

    @classmethod
    def _update_rules_file_version(cls, latest_version: str, file_url: str):
        capa_module = PythonModule.objects.get(
            module="capa_info.CapaInfo",
            base_path="api_app.analyzers_manager.file_analyzers",
        )

        _, created = AnalyzerRulesFileVersion.objects.update_or_create(
            python_module=capa_module,
            defaults={
                "last_downloaded_version": latest_version,
                "download_url": file_url,
                "downloaded_at": timezone.now(),
            },
        )

        if created:
            logger.info(f"Created new entry for {capa_module} rules file version")
        else:
            logger.info(f"Updated existing entry for {capa_module} rules file version")

    @classmethod
    def _unzip_rules(cls):
        logger.info(f"Extracting rules at {RULES_LOCATION}")
        with ZipFile(RULES_FILE, mode="r") as archive:
            archive.extractall(
                RULES_LOCATION
            )  # this will overwrite any existing directory
        logger.info("Rules have been succesfully extracted")

    @classmethod
    def _download_rules(cls, latest_version: str):

        if os.path.exists(RULES_LOCATION):
            logger.info(f"Removing existing rules at {RULES_LOCATION}")
            shutil.rmtree(RULES_LOCATION)

        os.makedirs(RULES_LOCATION)
        logger.info(f"Created fresh rules directory at {RULES_LOCATION}")

        file_to_download = latest_version + ".zip"
        file_url = RULES_URL + file_to_download
        try:

            response = requests.get(file_url, stream=True)
            logger.info(
                f"Started downloading rules with version: {latest_version} from {file_url}"
            )
            with open(RULES_FILE, mode="wb+") as file:
                for chunk in response.iter_content(chunk_size=10 * 1024):
                    file.write(chunk)

            cls._update_rules_file_version(latest_version, file_url)
            logger.info(f"Bumped up version number in db to {latest_version}")

        except Exception as e:
            logger.error(f"Failed to download rules with error: {e}")
            raise AnalyzerRunException("Failed to download rules")

        logger.info(
            f"Rules with version: {latest_version} have been successfully downloaded at {RULES_LOCATION}"
        )

    @classmethod
    def _download_signatures(cls) -> None:
        logger.info(f"Downloading signatures at {SIGNATURE_LOCATION} now")

        if os.path.exists(SIGNATURE_LOCATION):
            logger.info(f"Removing existing signatures at {SIGNATURE_LOCATION}")
            shutil.rmtree(SIGNATURE_LOCATION)

        os.makedirs(SIGNATURE_LOCATION)
        logger.info(f"Created fresh signatures directory at {SIGNATURE_LOCATION}")

        signatures_url = "https://api.github.com/repos/mandiant/capa/contents/sigs"
        try:
            response = requests.get(signatures_url)
            signatures_list = response.json()

            for signature in signatures_list:

                filename = signature["name"]
                download_url = signature["download_url"]

                signature_file_path = os.path.join(SIGNATURE_LOCATION, filename)

                sig_content = requests.get(download_url, stream=True)
                with open(signature_file_path, mode="wb") as file:
                    for chunk in sig_content.iter_content(chunk_size=10 * 1024):
                        file.write(chunk)

        except Exception as e:
            logger.error(f"Failed to download signature: {e}")
            raise AnalyzerRunException("Failed to update signatures")
        logger.info("Successfully updated signatures")

    @classmethod
    def update(cls) -> bool:
        try:
            logger.info("Updating capa rules")
            response = requests.get(
                "https://api.github.com/repos/mandiant/capa-rules/releases/latest"
            )
            latest_version = response.json()["tag_name"]
            cls._download_rules(latest_version)
            cls._unzip_rules()
            logger.info("Successfully updated capa rules")

            return True

        except Exception as e:
            logger.error(f"Failed to update capa rules with error: {e}")

        return False

    def run(self):
        try:

            response = requests.get(
                "https://api.github.com/repos/mandiant/capa-rules/releases/latest"
            )
            latest_version = response.json()["tag_name"]

            update_status = (
                True if self._check_if_latest_version(latest_version) else self.update()
            )

            if self.force_pull_signatures or not os.path.isdir(SIGNATURE_LOCATION):
                self._download_signatures()

            if not (os.path.isdir(RULES_LOCATION)) and not update_status:

                raise AnalyzerRunException("Couldn't update capa rules")

            command: list[str] = ["/usr/local/bin/capa", "--quiet", "--json"]
            shell_code_arch = "sc64" if self.arch == "64" else "sc32"
            if self.shellcode:
                command.append("-f")
                command.append(shell_code_arch)

            # Setting default capa-rules path
            command.append("-r")
            command.append(RULES_LOCATION)

            # Setting default signatures location
            command.append("-s")
            command.append(SIGNATURE_LOCATION)

            command.append(quote(self.filepath))

            logger.info(
                f"Starting CAPA analysis for {self.filename} with hash: {self.md5} and command: {command}"
            )

            process: subprocess.CompletedProcess = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True,
            )

            result = json.loads(process.stdout)
            result["command_executed"] = command
            result["rules_version"] = latest_version

            logger.info(
                f"CAPA analysis successfully completed for file: {self.filename} with hash {self.md5}"
            )

        except subprocess.CalledProcessError as e:
            stderr = e.stderr
            logger.info(
                f"Capa Info failed to run for {self.filename} with hash: {self.md5} with command {e}"
            )
            raise AnalyzerRunException(
                f" Analyzer for {self.filename} with hash: {self.md5} failed with error: {stderr}"
            )

        return result

    @classmethod
    def _monkeypatch(cls):
        response_from_command = subprocess.CompletedProcess(
            args=[
                "capa",
                "--quiet",
                "--json",
                "-r",
                "/opt/deploy/files_required/capa/capa-rules",
                "-s",
                "/opt/deploy/files_required/capa/sigs",
                "/opt/deploy/files_required/06ebf06587b38784e2af42dd5fbe56e5",
            ],
            returncode=0,
            stdout='{"meta": {}, "rules": {"contain obfuscated stackstrings": {}, "enumerate PE sections":{}}}',
            stderr="",
        )
        patches = [
            if_mock_connections(
                patch.object(CapaInfo, "update", return_value=True),
                patch("subprocess.run", return_value=response_from_command),
            )
        ]
        return super()._monkeypatch(patches)
