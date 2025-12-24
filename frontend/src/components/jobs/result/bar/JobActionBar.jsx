import React from "react";
import PropTypes from "prop-types";
import {
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
  UncontrolledDropdown,
} from "reactstrap";
import { useNavigate } from "react-router-dom";
import { TiThMenu } from "react-icons/ti";
import { IoMdSave } from "react-icons/io";
import { IconButton, addToast } from "@certego/certego-ui";

import { downloadJobSample, deleteJob, rescanJob } from "../jobApi";
import {
  JobResultSections,
  Classifications,
} from "../../../../constants/miscConst";
import {
  DeleteIcon,
  CommentIcon,
  rescanIcon,
  downloadReportIcon,
  downloadSampleIcon,
} from "../../../common/icon/actionIcons";
import { fileDownload } from "../../../../utils/files";
import { PluginConfigModal } from "../../../plugins/PluginConfigModal";
import { PluginsTypes } from "../../../../constants/pluginConst";
import {
  AnalyzableOverviewButton,
  InvestigationOverviewButton,
  RelatedInvestigationButton,
} from "../utils/jobButtons";

function SaveAsPlaybookIcon() {
  return (
    <span className="d-flex align-items-center text-light">
      <IoMdSave className="me-1" />
      Save as playbook
    </span>
  );
}

export function JobActionsBar({ job, relatedInvestigationNumber }) {
  console.debug(job);
  // routers
  const navigate = useNavigate();
  // state
  const [showModalCreatePlaybook, setShowModalCreatePlaybook] =
    React.useState(false);

  // callbacks
  const onDeleteBtnClick = async () => {
    const success = await deleteJob(job.id);
    if (!success) return;
    addToast("Redirecting...", null, "secondary");
    setTimeout(() => navigate(-1), 250);
  };

  const onDownloadSampleBtnClick = async () => {
    const blob = await downloadJobSample(job.id);
    if (!blob) return;
    let filename = "file";
    if (job?.file_name) {
      // it forces the name of the downloaded file
      filename = `${job.file_name}`;
    }
    fileDownload(blob, filename);
  };

  const handleRetry = async () => {
    addToast("Retrying the same job...", null, "spinner", false, 2000);
    const newJobId = await rescanJob(job.id);
    if (newJobId) {
      setTimeout(
        () => navigate(`/jobs/${newJobId}/${JobResultSections.VISUALIZER}/`),
        1000,
      );
    }
  };

  const onDownloadReport = () => {
    if (job) {
      const blob = new Blob([JSON.stringify(job)], { type: "text/json" });
      if (!blob) return;
      fileDownload(blob, `job#${job.id}_report.json`);
    }
  };

  const commentIcon = () => <CommentIcon commentNumber={job.comments.length} />;
  return (
    <div className="d-inline-flex">
      {job?.investigation_id && (
        <InvestigationOverviewButton
          id={job.investigation_id}
          name={job.investigation_name}
        />
      )}
      <RelatedInvestigationButton
        name={job.is_sample ? job.file_name : job.observable_name}
        relatedInvestigationNumber={relatedInvestigationNumber}
      />
      <AnalyzableOverviewButton id={job.analyzable_id} />
      <IconButton
        id="commentbtn"
        Icon={commentIcon}
        size="sm"
        color="info"
        className="me-1 text-light"
        onClick={() => navigate(`/jobs/${job.id}/comments`)}
        title="Artifact Comments"
        titlePlacement="top"
      />
      <UncontrolledDropdown inNavbar>
        <DropdownToggle nav className="text-center">
          <IconButton
            id="jobActions"
            Icon={TiThMenu}
            size="sm"
            color="light"
            title="Job actions"
            titlePlacement="top"
          />
        </DropdownToggle>
        <DropdownMenu end className="bg-dark" data-bs-popper>
          <DropdownItem className="bg-transparent">
            <IconButton
              id="downloadreportbtn"
              Icon={downloadReportIcon}
              size="sm"
              color="accent-2"
              onClick={onDownloadReport}
              title="Download report in json format"
              titlePlacement="top"
            />
          </DropdownItem>
          {job?.is_sample && (
            <DropdownItem className="bg-transparent">
              <IconButton
                id="downloadsamplebtn"
                Icon={downloadSampleIcon}
                size="sm"
                color="accent-2"
                onClick={onDownloadSampleBtnClick}
                title="Download sample"
                titlePlacement="top"
              />
            </DropdownItem>
          )}
          <DropdownItem className="bg-transparent">
            <IconButton
              id="saveAsAPlaybook"
              Icon={SaveAsPlaybookIcon}
              size="sm"
              color="info"
              onClick={() => setShowModalCreatePlaybook(true)}
              title="Save current analysis configurations as a playbook"
              titlePlacement="top"
            />
            <PluginConfigModal
              pluginConfig={{
                analyzers: job?.analyzers_to_execute,
                connectors: job?.connectors_to_execute,
                pivots: job?.pivots_to_execute,
                type: [
                  job?.is_sample
                    ? Classifications.FILE
                    : job?.observable_classification,
                ],
                runtimeConfiguration: job?.runtime_configuration,
                tags: job?.tags.map((tag) => tag?.label),
                tlp: job?.tlp,
                scan_mode: job?.scan_mode,
                scan_check_time: job?.scan_check_time,
              }}
              pluginType={PluginsTypes.PLAYBOOK}
              toggle={setShowModalCreatePlaybook}
              isOpen={showModalCreatePlaybook}
            />
          </DropdownItem>
          <DropdownItem className="bg-transparent">
            <IconButton
              id="rescanbtn"
              Icon={rescanIcon}
              onClick={handleRetry}
              color="info"
              size="sm"
              title="Force run the same analysis"
              titlePlacement="top"
              className="text-light"
            />
          </DropdownItem>
          {job.permissions?.delete && (
            <DropdownItem className="bg-transparent">
              <IconButton
                id="deletejobbtn"
                Icon={DeleteIcon}
                size="sm"
                color="light"
                onClick={onDeleteBtnClick}
                title="Delete Job"
                titlePlacement="top"
              />
            </DropdownItem>
          )}
        </DropdownMenu>
      </UncontrolledDropdown>
    </div>
  );
}

JobActionsBar.propTypes = {
  job: PropTypes.object.isRequired,
  relatedInvestigationNumber: PropTypes.number.isRequired,
};
