import React from "react";
import PropTypes from "prop-types";
import { Button, UncontrolledTooltip } from "reactstrap";
import { CiViewTimeline } from "react-icons/ci";
import { CgListTree } from "react-icons/cg";
import { FaObjectUngroup } from "react-icons/fa";
import { fromZonedTime } from "date-fns-tz";

import { localTimezone } from "../../../../constants/miscConst";

export function InvestigationOverviewButton({ id, name }) {
  return (
    <Button
      className="bg-body border-1 lh-sm me-1 d-flex align-items-center"
      href={`/investigation/${id}`}
      target="_blank"
      rel="noreferrer"
      id="investigationOverviewBtn"
      size="xs"
      style={{ fontSize: "0.8rem" }}
    >
      <CgListTree className="me-1" />
      Investigation overview
      <UncontrolledTooltip placement="top" target="investigationOverviewBtn">
        This job is part of the investigation: {name}
      </UncontrolledTooltip>
    </Button>
  );
}

InvestigationOverviewButton.propTypes = {
  id: PropTypes.number.isRequired,
  name: PropTypes.string.isRequired,
};

export function RelatedInvestigationButton({
  name,
  relatedInvestigationNumber,
}) {
  const investigationTimeRange = 30;
  const endDateRelatedInvestigation = new Date();
  const startDateRelatedInvestigation = structuredClone(
    endDateRelatedInvestigation,
  );
  startDateRelatedInvestigation.setDate(
    startDateRelatedInvestigation.getDate() - investigationTimeRange,
  );

  const url = `/history/investigations?start_time__gte=${encodeURIComponent(
    fromZonedTime(startDateRelatedInvestigation, localTimezone).toISOString(),
  )}&start_time__lte=${encodeURIComponent(
    fromZonedTime(endDateRelatedInvestigation, localTimezone).toISOString(),
  )}&analyzed_object_name=${name}&ordering=-start_time`;

  console.debug(url);
  return (
    <Button
      className="bg-body border-1 lh-sm me-1 d-flex align-items-center"
      href={url}
      target="_blank"
      rel="noreferrer"
      id="investigationSearchBtn"
      size="xs"
      style={{ fontSize: "0.8rem" }}
    >
      <FaObjectUngroup className="me-1" />
      Related investigations: {relatedInvestigationNumber}
      <UncontrolledTooltip placement="top" target="investigationSearchBtn">
        Search investigations for {name} in the last
        {` ${investigationTimeRange}`} days.
      </UncontrolledTooltip>
    </Button>
  );
}

RelatedInvestigationButton.propTypes = {
  name: PropTypes.string.isRequired,
  relatedInvestigationNumber: PropTypes.number.isRequired,
};

export function AnalyzableOverviewButton({ id }) {
  return (
    <Button
      className="bg-secondary lh-sm me-1 d-flex align-items-center"
      href={`/artifacts/${id}`}
      target="_blank"
      rel="noreferrer"
      id="analyzableOverviewBtn"
      size="xs"
      style={{ fontSize: "0.8rem" }}
    >
      <CiViewTimeline className="me-1" />
      Evaluation history
      <UncontrolledTooltip placement="top" target="analyzableOverviewBtn">
        Show all evaluations for this artifact
      </UncontrolledTooltip>
    </Button>
  );
}

AnalyzableOverviewButton.propTypes = {
  id: PropTypes.number.isRequired,
};
