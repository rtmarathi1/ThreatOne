#include <doctest/doctest.h>
#include <soc/WorkflowAutomation.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("WorkflowAutomation - Create workflow") {
    WorkflowAutomation wf;

    WorkflowDefinition def;
    def.name = "Auto Escalation";
    def.description = "Escalate critical cases";

    WorkflowTrigger trigger;
    trigger.type = TriggerType::SeverityEscalation;
    def.triggers.push_back(trigger);

    WorkflowAction action;
    action.name = "Notify Lead";
    action.actionType = "notify";
    def.actions.push_back(action);

    std::string id = wf.createWorkflow(def);
    CHECK_FALSE(id.empty());
    CHECK(id.find("WF-") == 0);
}

TEST_CASE("WorkflowAutomation - Delete workflow") {
    WorkflowAutomation wf;

    WorkflowDefinition def;
    def.name = "To Delete";
    std::string id = wf.createWorkflow(def);

    CHECK(wf.deleteWorkflow(id));
    CHECK_FALSE(wf.workflowExists(id));
    CHECK_FALSE(wf.deleteWorkflow("nonexistent"));
}

TEST_CASE("WorkflowAutomation - Enable and disable workflow") {
    WorkflowAutomation wf;

    WorkflowDefinition def;
    def.name = "Toggle Test";
    def.enabled = true;
    std::string id = wf.createWorkflow(def);

    CHECK(wf.disableWorkflow(id));
    auto fetched = wf.getWorkflow(id);
    CHECK_FALSE(fetched.enabled);

    CHECK(wf.enableWorkflow(id));
    fetched = wf.getWorkflow(id);
    CHECK(fetched.enabled);

    CHECK_FALSE(wf.enableWorkflow("nonexistent"));
    CHECK_FALSE(wf.disableWorkflow("nonexistent"));
}

TEST_CASE("WorkflowAutomation - Get workflows") {
    WorkflowAutomation wf;

    WorkflowDefinition def1;
    def1.name = "WF1";
    wf.createWorkflow(def1);

    WorkflowDefinition def2;
    def2.name = "WF2";
    wf.createWorkflow(def2);

    auto workflows = wf.getWorkflows();
    CHECK(workflows.size() == 2);
}

TEST_CASE("WorkflowAutomation - Workflow exists check") {
    WorkflowAutomation wf;

    WorkflowDefinition def;
    def.name = "Exists Test";
    std::string id = wf.createWorkflow(def);

    CHECK(wf.workflowExists(id));
    CHECK_FALSE(wf.workflowExists("nonexistent"));
}

TEST_CASE("WorkflowAutomation - Get workflow for case status") {
    WorkflowAutomation wf;

    auto workflow = wf.getWorkflowForCase("CASE-1", CaseStatus::Open);
    CHECK(workflow.currentStep == "Triage");
    CHECK(workflow.steps.size() == 5);

    workflow = wf.getWorkflowForCase("CASE-1", CaseStatus::Investigating);
    CHECK(workflow.currentStep == "Investigate");

    workflow = wf.getWorkflowForCase("CASE-1", CaseStatus::Escalated);
    CHECK(workflow.currentStep == "Contain");

    workflow = wf.getWorkflowForCase("CASE-1", CaseStatus::Resolved);
    CHECK(workflow.currentStep == "Remediate");

    workflow = wf.getWorkflowForCase("CASE-1", CaseStatus::Closed);
    CHECK(workflow.currentStep == "Close");
}

TEST_CASE("WorkflowAutomation - Evaluate triggers") {
    WorkflowAutomation wf;

    WorkflowDefinition def;
    def.name = "Alert Workflow";
    def.enabled = true;

    WorkflowTrigger trigger;
    trigger.type = TriggerType::CaseCreated;
    def.triggers.push_back(trigger);

    wf.createWorkflow(def);

    // Matching trigger
    CHECK(wf.evaluateTriggers(TriggerType::CaseCreated, "CASE-1"));
    // Non-matching trigger
    CHECK_FALSE(wf.evaluateTriggers(TriggerType::TimeElapsed, "timeout"));
}

TEST_CASE("WorkflowAutomation - Workflow count") {
    WorkflowAutomation wf;
    CHECK(wf.getWorkflowCount() == 0);

    WorkflowDefinition def1;
    def1.name = "WF1";
    def1.enabled = true;
    wf.createWorkflow(def1);

    WorkflowDefinition def2;
    def2.name = "WF2";
    def2.enabled = false;
    wf.createWorkflow(def2);

    CHECK(wf.getWorkflowCount() == 2);
    CHECK(wf.getActiveWorkflowCount() == 1);
}
