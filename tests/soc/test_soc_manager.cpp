#include <doctest/doctest.h>
#include <soc/SOCManager.h>

using namespace ThreatOne::SOC;

TEST_CASE("SOCManager - Create case") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Suspicious login";
    info.description = "Multiple failed logins detected";
    info.severity = "high";

    std::string id = mgr.createCase(info);
    CHECK_FALSE(id.empty());
    CHECK(id.find("CASE-") == 0);
}

TEST_CASE("SOCManager - Create multiple cases returns unique IDs") {
    SOCManager mgr;

    CaseInfo info1;
    info1.title = "Case 1";
    info1.severity = "low";

    CaseInfo info2;
    info2.title = "Case 2";
    info2.severity = "medium";

    std::string id1 = mgr.createCase(info1);
    std::string id2 = mgr.createCase(info2);
    CHECK(id1 != id2);
}

TEST_CASE("SOCManager - Case lifecycle: Open to Investigating") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Lifecycle test";
    info.severity = "critical";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Investigating));
}

TEST_CASE("SOCManager - Case lifecycle: full path") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Full lifecycle test";
    info.severity = "critical";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Investigating));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Escalated));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Resolved));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Closed));
}

TEST_CASE("SOCManager - Case lifecycle: cannot reopen closed case") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Reopen test";
    info.severity = "critical";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Investigating));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Resolved));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Closed));
    CHECK_FALSE(mgr.updateCaseStatus(id, CaseStatus::Open));
}

TEST_CASE("SOCManager - Case lifecycle: resolved can only go to closed") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Resolved transition test";
    info.severity = "critical";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Resolved));
    CHECK_FALSE(mgr.updateCaseStatus(id, CaseStatus::Investigating));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Closed));
}

TEST_CASE("SOCManager - Update status on nonexistent case fails") {
    SOCManager mgr;
    CHECK_FALSE(mgr.updateCaseStatus("nonexistent", CaseStatus::Investigating));
}

TEST_CASE("SOCManager - Assign case") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Assign test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.assignCase(id, "analyst-01"));

    SUBCASE("Assign nonexistent case fails") {
        CHECK_FALSE(mgr.assignCase("nonexistent", "analyst-01"));
    }
}

TEST_CASE("SOCManager - Escalate case") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Escalation test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.escalate(id, "Potential APT activity"));

    SUBCASE("Escalate nonexistent case fails") {
        CHECK_FALSE(mgr.escalate("nonexistent", "reason"));
    }
}

TEST_CASE("SOCManager - Get workflow reflects case status") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Workflow test";
    std::string id = mgr.createCase(info);

    auto workflow = mgr.getWorkflow(id);
    CHECK(workflow.currentStep == "Triage");
    CHECK(workflow.steps.size() == 5);

    mgr.updateCaseStatus(id, CaseStatus::Investigating);
    workflow = mgr.getWorkflow(id);
    CHECK(workflow.currentStep == "Investigate");
}

TEST_CASE("SOCManager - Get workflow for nonexistent case returns empty") {
    SOCManager mgr;
    auto workflow = mgr.getWorkflow("nonexistent");
    CHECK(workflow.id.empty());
}

TEST_CASE("SOCManager - Get metrics") {
    SOCManager mgr;

    CaseInfo info1;
    info1.title = "Open case";
    std::string id1 = mgr.createCase(info1);
    mgr.assignCase(id1, "analyst-01");

    CaseInfo info2;
    info2.title = "Closed case";
    std::string id2 = mgr.createCase(info2);
    mgr.updateCaseStatus(id2, CaseStatus::Resolved);
    mgr.updateCaseStatus(id2, CaseStatus::Closed);

    auto metrics = mgr.getMetrics();
    CHECK(metrics.openCases == 1);
    CHECK(metrics.closedCases == 1);
    CHECK(metrics.activeAnalysts == 1);
}

TEST_CASE("SOCManager - Add and get evidence") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "Evidence test";
    std::string caseId = mgr.createCase(info);

    EvidenceItem ev1;
    ev1.type = "log";
    ev1.description = "Firewall log entry";
    ev1.data = "SRC=192.168.1.1 DST=10.0.0.1";
    ev1.addedBy = "analyst-01";

    EvidenceItem ev2;
    ev2.type = "pcap";
    ev2.description = "Network capture";
    ev2.data = "binary_data_here";
    ev2.addedBy = "analyst-02";

    std::string evId1 = mgr.addEvidence(caseId, ev1);
    std::string evId2 = mgr.addEvidence(caseId, ev2);

    CHECK_FALSE(evId1.empty());
    CHECK_FALSE(evId2.empty());
    CHECK(evId1 != evId2);

    auto evidence = mgr.getEvidence(caseId);
    CHECK(evidence.size() == 2);
    CHECK(evidence[0].type == "log");
    CHECK(evidence[1].type == "pcap");
    CHECK(evidence[0].caseId == caseId);
}

TEST_CASE("SOCManager - Add evidence to nonexistent case fails") {
    SOCManager mgr;

    EvidenceItem ev;
    ev.type = "log";
    std::string id = mgr.addEvidence("nonexistent", ev);
    CHECK(id.empty());
}

TEST_CASE("SOCManager - Get evidence for case with no evidence returns empty") {
    SOCManager mgr;

    CaseInfo info;
    info.title = "No evidence";
    std::string caseId = mgr.createCase(info);

    auto evidence = mgr.getEvidence(caseId);
    CHECK(evidence.empty());
}

TEST_CASE("SOCManager - Create and get playbooks") {
    SOCManager mgr;

    Playbook pb;
    pb.name = "Malware Response";
    pb.description = "Steps to respond to malware";
    pb.triggerCondition = "severity=critical";

    PlaybookStep step1;
    step1.name = "Isolate Endpoint";
    step1.actionType = "isolate";
    step1.description = "Isolate the affected endpoint";
    pb.steps.push_back(step1);

    PlaybookStep step2;
    step2.name = "Collect Evidence";
    step2.actionType = "collect";
    step2.description = "Gather forensic evidence";
    pb.steps.push_back(step2);

    std::string id = mgr.createPlaybook(pb);
    CHECK_FALSE(id.empty());
    CHECK(id.find("PB-") == 0);

    auto playbooks = mgr.getPlaybooks();
    CHECK(playbooks.size() == 1);
    CHECK(playbooks[0].name == "Malware Response");
    CHECK(playbooks[0].steps.size() == 2);
}

TEST_CASE("SOCManager - Execute playbook runs steps in order") {
    SOCManager mgr;

    CaseInfo caseInfo;
    caseInfo.title = "Playbook execution test";
    std::string caseId = mgr.createCase(caseInfo);

    Playbook pb;
    pb.name = "Incident Response";

    PlaybookStep step1;
    step1.name = "Triage";
    step1.actionType = "triage";
    pb.steps.push_back(step1);

    PlaybookStep step2;
    step2.name = "Investigate";
    step2.actionType = "investigate";
    pb.steps.push_back(step2);

    PlaybookStep step3;
    step3.name = "Remediate";
    step3.actionType = "fix";
    pb.steps.push_back(step3);

    std::string pbId = mgr.createPlaybook(pb);
    std::string execId = mgr.executePlaybook(pbId, caseId);

    CHECK_FALSE(execId.empty());
    CHECK(execId.find("EXEC-") == 0);

    auto exec = mgr.getPlaybookExecution(execId);
    CHECK(exec.id == execId);
    CHECK(exec.playbookId == pbId);
    CHECK(exec.caseId == caseId);
    CHECK(exec.status == ExecutionStatus::Completed);
    CHECK(exec.results.size() == 3);
    CHECK(exec.results[0].find("Triage") != std::string::npos);
    CHECK(exec.results[1].find("Investigate") != std::string::npos);
    CHECK(exec.results[2].find("Remediate") != std::string::npos);
}

TEST_CASE("SOCManager - Execute playbook with condition skips steps") {
    SOCManager mgr;

    CaseInfo caseInfo;
    caseInfo.title = "Conditional playbook test";
    std::string caseId = mgr.createCase(caseInfo);

    Playbook pb;
    pb.name = "Conditional Response";

    PlaybookStep step1;
    step1.name = "Always Run";
    step1.actionType = "action1";
    pb.steps.push_back(step1);

    PlaybookStep step2;
    step2.name = "Skipped Step";
    step2.actionType = "action2";
    step2.condition = "skip";
    pb.steps.push_back(step2);

    PlaybookStep step3;
    step3.name = "Also Runs";
    step3.actionType = "action3";
    pb.steps.push_back(step3);

    std::string pbId = mgr.createPlaybook(pb);
    std::string execId = mgr.executePlaybook(pbId, caseId);

    auto exec = mgr.getPlaybookExecution(execId);
    CHECK(exec.status == ExecutionStatus::Completed);
    CHECK(exec.results.size() == 3);
    CHECK(exec.results[0].find("completed") != std::string::npos);
    CHECK(exec.results[1].find("skipped") != std::string::npos);
    CHECK(exec.results[2].find("completed") != std::string::npos);
}

TEST_CASE("SOCManager - Execute playbook with nonexistent playbook fails") {
    SOCManager mgr;

    CaseInfo caseInfo;
    caseInfo.title = "Invalid playbook test";
    std::string caseId = mgr.createCase(caseInfo);

    std::string execId = mgr.executePlaybook("nonexistent", caseId);
    CHECK(execId.empty());
}

TEST_CASE("SOCManager - Execute playbook with nonexistent case fails") {
    SOCManager mgr;

    Playbook pb;
    pb.name = "Test PB";
    std::string pbId = mgr.createPlaybook(pb);

    std::string execId = mgr.executePlaybook(pbId, "nonexistent");
    CHECK(execId.empty());
}

TEST_CASE("SOCManager - Get playbook execution for nonexistent ID returns empty") {
    SOCManager mgr;
    auto exec = mgr.getPlaybookExecution("nonexistent");
    CHECK(exec.id.empty());
}

TEST_CASE("SOCManager - Create shifts and get shifts") {
    SOCManager mgr;

    ShiftInfo shift1;
    shift1.name = "Morning Shift";
    shift1.startTime = "06:00";
    shift1.endTime = "14:00";
    shift1.analysts = {"analyst-01", "analyst-02"};

    ShiftInfo shift2;
    shift2.name = "Evening Shift";
    shift2.startTime = "14:00";
    shift2.endTime = "22:00";
    shift2.analysts = {"analyst-03"};

    std::string id1 = mgr.createShift(shift1);
    std::string id2 = mgr.createShift(shift2);

    CHECK_FALSE(id1.empty());
    CHECK_FALSE(id2.empty());
    CHECK(id1 != id2);

    auto shifts = mgr.getShifts();
    CHECK(shifts.size() == 2);
}

TEST_CASE("SOCManager - Add and get handoff notes") {
    SOCManager mgr;

    ShiftInfo shift;
    shift.name = "Day Shift";
    shift.startTime = "08:00";
    shift.endTime = "16:00";
    std::string shiftId = mgr.createShift(shift);

    HandoffNote note1;
    note1.fromAnalyst = "analyst-01";
    note1.toAnalyst = "analyst-02";
    note1.shiftId = shiftId;
    note1.notes = "Case CASE-001 still under investigation";
    note1.openCases = {"CASE-001"};

    HandoffNote note2;
    note2.fromAnalyst = "analyst-01";
    note2.toAnalyst = "analyst-03";
    note2.shiftId = shiftId;
    note2.notes = "New phishing campaign detected";
    note2.openCases = {"CASE-001", "CASE-002"};

    std::string noteId1 = mgr.addHandoffNote(note1);
    std::string noteId2 = mgr.addHandoffNote(note2);

    CHECK_FALSE(noteId1.empty());
    CHECK(noteId1.find("HN-") == 0);
    CHECK(noteId1 != noteId2);

    auto notes = mgr.getHandoffNotes(shiftId);
    CHECK(notes.size() == 2);
    CHECK(notes[0].fromAnalyst == "analyst-01");
    CHECK(notes[0].openCases.size() == 1);
    CHECK(notes[1].openCases.size() == 2);
}

TEST_CASE("SOCManager - Get handoff notes for nonexistent shift returns empty") {
    SOCManager mgr;
    auto notes = mgr.getHandoffNotes("nonexistent");
    CHECK(notes.empty());
}

TEST_CASE("SOCManager - Create and sync tickets") {
    SOCManager mgr;

    CaseInfo caseInfo;
    caseInfo.title = "Ticket test";
    std::string caseId = mgr.createCase(caseInfo);

    TicketInfo ticket;
    ticket.externalId = "JIRA-1234";
    ticket.system = "Jira";
    ticket.title = "Investigate suspicious activity";
    ticket.status = "open";
    ticket.url = "https://jira.example.com/JIRA-1234";
    ticket.caseId = caseId;

    std::string ticketId = mgr.createTicket(ticket);
    CHECK_FALSE(ticketId.empty());
    CHECK(ticketId.find("TKT-") == 0);

    SUBCASE("Sync ticket updates status") {
        CHECK(mgr.syncTicket(ticketId));

        auto tickets = mgr.getTickets(caseId);
        REQUIRE(tickets.size() == 1);
        CHECK(tickets[0].status == "synced");
        CHECK(tickets[0].lastSyncAt == "synced");
    }

    SUBCASE("Sync nonexistent ticket fails") {
        CHECK_FALSE(mgr.syncTicket("nonexistent"));
    }
}

TEST_CASE("SOCManager - Get tickets for case") {
    SOCManager mgr;

    CaseInfo caseInfo;
    caseInfo.title = "Multi-ticket case";
    std::string caseId = mgr.createCase(caseInfo);

    TicketInfo ticket1;
    ticket1.system = "Jira";
    ticket1.title = "Ticket 1";
    ticket1.caseId = caseId;

    TicketInfo ticket2;
    ticket2.system = "ServiceNow";
    ticket2.title = "Ticket 2";
    ticket2.caseId = caseId;

    TicketInfo ticket3;
    ticket3.system = "Jira";
    ticket3.title = "Other case ticket";
    ticket3.caseId = "OTHER-CASE";

    mgr.createTicket(ticket1);
    mgr.createTicket(ticket2);
    mgr.createTicket(ticket3);

    auto tickets = mgr.getTickets(caseId);
    CHECK(tickets.size() == 2);
}

TEST_CASE("SOCManager - Get tickets for case with no tickets returns empty") {
    SOCManager mgr;
    auto tickets = mgr.getTickets("nonexistent-case");
    CHECK(tickets.empty());
}
