import logging

from jbxapi import JoeSandbox

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.mixins import JoeSandboxMixin
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class JoeSandboxFile(FileAnalyzer, JoeSandboxMixin):
    url: str

    @classmethod
    def update(cls):
        pass

    def run(self):
        sandbox_session = JoeSandbox(
            apiurl=self.url, apikey=self._api_key, accept_tac=True
        )
        sample_file = self._job.analyzable.file

        try:

            # return submission results if there exists a submission with same file observable
            analysis_id = self.check_submission_exists(
                sandbox_session, file_name=self.filename
            )
            if analysis_id:
                return {analysis_id: sandbox_session.analysis_info(analysis_id)}

            logger.info("Existing submission not found")

            # return analysis result if analysis is present in public DB
            logger.info(f"Checking if analysis is present for {self.filename}")
            analysis_ids = self.check_if_analysis_present(
                session=sandbox_session, file_hash=self.md5
            )
            if analysis_ids:
                analysis_result = {}
                for id in analysis_ids:
                    analysis_result[id] = sandbox_session.analysis_info(id)
                return analysis_result

            # submit new sample if no existing analysis
            else:
                logger.info(f"Creating new submission for {self.filename}")
                params = {"systems": self.system_to_use}
                submission = sandbox_session.submit_sample(
                    (self.filename, sample_file), params=params, _chunked_upload=True
                )

                submission_info = sandbox_session.submission_info(
                    submission["submission_id"]
                )
                most_relevant_analysis_id = submission_info["most_relevant_analysis"][
                    "webid"
                ]

                logger.info(
                    f"Sample submitted successfully with analysis_id: {most_relevant_analysis_id}"
                )

                if self.wait_for_analysis_to_finish(
                    sandbox_session, submission["submission_id"]
                ):
                    logger.info(f"Analysis completed successfully for {self.filename}")
                    return sandbox_session.analysis_info(most_relevant_analysis_id)

        except Exception as e:
            raise AnalyzerRunException(f"Something went wrong: {e}")

    @classmethod
    def _monkeypatch(cls):

        submission_info_response = {
            "submission_id": "178",
            "name": "Sample.exe",
            "status": "finished",
            "time": "2019-04-15T08:05:05+00:00",
            # // present for any status after 'accepted',
            # // can be null if there are no analyses
            "most_relevant_analysis": {
                "webid": "179",
                "detection": "clean",
                "score": 30,
            },
            # // present for any status after 'accepted'
            "analyses": [
                {
                    "webid": "179",
                    "time": "2019-04-15T08:05:08+00:00",
                    "runs": [
                        {
                            "detection": "clean",
                            "error": None,
                            "system": "w7",
                            "yara": False,
                        },
                        {
                            "detection": "clean",
                            "error": None,
                            "system": "w7x64",
                            "yara": False,
                        },
                    ],
                    "tags": [],
                    "analysisid": "127",
                    "duration": 1,
                    "encrypted": False,
                    "md5": "098f6bcd4621d373cade4e832627b4f6",
                    "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
                    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "filename": "Sample.exe",
                    "scriptname": "defaultwindowsofficecookbook.jbs",
                    "status": "finished",
                    "comments": "",
                    # // Present while Live Interaction is active
                    "live-interaction-url": "https://joesandbox.com/analysis/123456789",
                },
            ],
        }

        analysis_info_response = {
            "webid": "100",
            "analysisid": "4",
            "status": "finished",
            "detection": "malicious",
            "score": 42,
            "classification": "",
            "threatname": "Unknown",
            "comments": "a sample comment",
            "filename": "sample.exe",
            "scriptname": "default.jbs",
            "time": "2017-08-11T16:06:32+02:00",
            "duration": 150,
            "encrypted": False,
            "md5": "0cbc6611f5540bd0809a388dc95a615b",
            "sha1": "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa",
            "sha256": "532eaabd9574880 [...] 299550d7a6e0f345e25",
            "tags": ["internal", "important"],
            # Present while Live Interaction is active
            "live-interaction-url": "https://joesandbox.com/analysis/123456789",
            "runs": [
                {
                    "detection": "unknown",
                    "error": "Unable to run",
                    "system": "w7",
                    "yara": False,
                    "sigma": False,
                    "score": 1,
                },
                {
                    "detection": "malicious",
                    "error": None,
                    "system": "w7x64",
                    "yara": False,
                    "sigma": False,
                    "score": 42,
                },
            ],
        }

        patches = [
            if_mock_connections(
                patch.object(
                    JoeSandboxFile, "check_submission_exists", return_value=None
                ),
                patch.object(
                    JoeSandboxFile, "check_if_analysis_present", return_value=None
                ),
                patch.object(
                    JoeSandbox, "submit_sample", return_value={"submission_id": "178"}
                ),
                patch.object(
                    JoeSandboxFile, "wait_for_analysis_to_finish", return_value=True
                ),
                patch.object(
                    JoeSandbox, "submission_info", return_value=submission_info_response
                ),
                patch.object(
                    JoeSandbox, "analysis_info", return_value=analysis_info_response
                ),
            )
        ]
        return super()._monkeypatch(patches)
