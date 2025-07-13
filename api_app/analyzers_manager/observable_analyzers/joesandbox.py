import logging

from jbxapi import JoeSandbox

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.mixins import JoeSandboxMixin
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class JoeSandboxAnalyzer(ObservableAnalyzer, JoeSandboxMixin):
    url: str
    sample_at_url: bool = False

    def submit_observable(self, sandbox_session: JoeSandbox) -> str:
        logger.info(f"Submitting observable: {self.observable_name}")
        params = {"systems": self.system_to_use}
        submission: dict = (
            sandbox_session.submit_sample_url(self.observable_name, params=params)
            if self.sample_at_url
            else sandbox_session.submit_url(self.observable_name, params=params)
        )

        logger.info(
            f"Observable submitted successfully with submission id: {submission['submission_id']}"
        )
        return submission["submission_id"]

    @classmethod
    def update(cls):
        pass

    def run(self):
        sandbox_session = JoeSandbox(
            apikey=self._api_key, apiurl=self.url, accept_tac=True
        )

        # checking if similar submission in account is already present
        analysis_id = self.check_submission_exists(
            session=sandbox_session, observable_url=self.observable_name
        )
        if analysis_id:
            return {analysis_id: sandbox_session.analysis_info(analysis_id)}

        logger.info("Existing submission not found")

        # checking if similar analysis is present in public DB
        logger.info(f"Checking if analysis is present for {self.observable_name}")

        analysis_ids = self.check_if_analysis_present(
            session=sandbox_session, observable_url=self.observable_name
        )
        if analysis_ids:
            analysis_result = {}
            for id in analysis_ids:
                analysis_result[id] = sandbox_session.analysis_info(id)
            return analysis_result

        # submitting a new sample, if no exisiting analysis is present
        else:
            logger.info(f"Creating new submission for {self.observable_name}")
            submission_id = self.submit_observable(sandbox_session)

            try:
                if self.wait_for_analysis_to_finish(sandbox_session, submission_id):
                    logger.info(
                        f"Analysis completed successfully for {self.observable_name}"
                    )
                    submission_info = sandbox_session.submission_info(submission_id)
                    most_relevant_analysis_id = submission_info[
                        "most_relevant_analysis"
                    ]["webid"]
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
                }
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
                    JoeSandboxAnalyzer, "check_submission_exists", return_value=None
                ),
                patch.object(
                    JoeSandboxAnalyzer, "check_if_analysis_present", return_value=None
                ),
                patch.object(
                    JoeSandboxAnalyzer, "submit_observable", return_value="1009"
                ),
                patch.object(
                    JoeSandboxAnalyzer, "wait_for_analysis_to_finish", return_value=True
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
