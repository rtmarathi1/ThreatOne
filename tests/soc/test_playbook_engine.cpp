#include <doctest/doctest.h>
#include <soc/PlaybookEngine.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("PlaybookEngine - Create playbook") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "Malware Response";
    pb.description = "Steps to respond to malware";

    PlaybookStep step1;
    step1.name = "Isolate";
    step1.actionType = "isolate";
    pb.steps.push_back(step1);

    std::string id = engine.createPlaybook(pb);
    CHECK_FALSE(id.empty());
    CHECK(id.find("PB-") == 0);
}

TEST_CASE("PlaybookEngine - Get playbooks") {
    PlaybookEngine engine;

    Playbook pb1;
    pb1.name = "Playbook 1";
    engine.createPlaybook(pb1);

    Playbook pb2;
    pb2.name = "Playbook 2";
    engine.createPlaybook(pb2);

    auto playbooks = engine.getPlaybooks();
    CHECK(playbooks.size() == 2);
}

TEST_CASE("PlaybookEngine - Delete playbook") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "To Delete";
    std::string id = engine.createPlaybook(pb);

    CHECK(engine.deletePlaybook(id));
    CHECK_FALSE(engine.playbookExists(id));
    CHECK_FALSE(engine.deletePlaybook("nonexistent"));
}

TEST_CASE("PlaybookEngine - Playbook exists check") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "Exists Test";
    std::string id = engine.createPlaybook(pb);

    CHECK(engine.playbookExists(id));
    CHECK_FALSE(engine.playbookExists("nonexistent"));
}

TEST_CASE("PlaybookEngine - Execute playbook runs all steps") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "Full Execution";

    PlaybookStep step1;
    step1.name = "Triage";
    step1.actionType = "triage";
    pb.steps.push_back(step1);

    PlaybookStep step2;
    step2.name = "Investigate";
    step2.actionType = "investigate";
    pb.steps.push_back(step2);

    std::string pbId = engine.createPlaybook(pb);
    std::string execId = engine.executePlaybook(pbId, "CASE-1");

    CHECK_FALSE(execId.empty());
    CHECK(execId.find("EXEC-") == 0);

    auto exec = engine.getPlaybookExecution(execId);
    CHECK(exec.status == ExecutionStatus::Completed);
    CHECK(exec.results.size() == 2);
    CHECK(exec.results[0].find("Triage") != std::string::npos);
    CHECK(exec.results[1].find("Investigate") != std::string::npos);
}

TEST_CASE("PlaybookEngine - Execute playbook with skip condition") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "Conditional";

    PlaybookStep step1;
    step1.name = "Always";
    step1.actionType = "action1";
    pb.steps.push_back(step1);

    PlaybookStep step2;
    step2.name = "Skipped";
    step2.actionType = "action2";
    step2.condition = "skip";
    pb.steps.push_back(step2);

    PlaybookStep step3;
    step3.name = "Also Runs";
    step3.actionType = "action3";
    pb.steps.push_back(step3);

    std::string pbId = engine.createPlaybook(pb);
    std::string execId = engine.executePlaybook(pbId, "CASE-1");

    auto exec = engine.getPlaybookExecution(execId);
    CHECK(exec.status == ExecutionStatus::Completed);
    CHECK(exec.results.size() == 3);
    CHECK(exec.results[0].find("completed") != std::string::npos);
    CHECK(exec.results[1].find("skipped") != std::string::npos);
    CHECK(exec.results[2].find("completed") != std::string::npos);
}

TEST_CASE("PlaybookEngine - Execute nonexistent playbook fails") {
    PlaybookEngine engine;
    std::string execId = engine.executePlaybook("nonexistent", "CASE-1");
    CHECK(execId.empty());
}

TEST_CASE("PlaybookEngine - Get nonexistent execution returns empty") {
    PlaybookEngine engine;
    auto exec = engine.getPlaybookExecution("nonexistent");
    CHECK(exec.id.empty());
}

TEST_CASE("PlaybookEngine - Get executions for case") {
    PlaybookEngine engine;

    Playbook pb;
    pb.name = "Multi-exec";
    PlaybookStep step;
    step.name = "Step";
    step.actionType = "action";
    pb.steps.push_back(step);

    std::string pbId = engine.createPlaybook(pb);
    engine.executePlaybook(pbId, "CASE-1");
    engine.executePlaybook(pbId, "CASE-1");
    engine.executePlaybook(pbId, "CASE-2");

    auto execs = engine.getExecutionsForCase("CASE-1");
    CHECK(execs.size() == 2);
}

TEST_CASE("PlaybookEngine - Validate playbook") {
    PlaybookEngine engine;

    Playbook valid;
    valid.name = "Valid";
    PlaybookStep step;
    step.name = "Step1";
    valid.steps.push_back(step);
    CHECK(engine.validatePlaybook(valid));

    Playbook noName;
    CHECK_FALSE(engine.validatePlaybook(noName));

    Playbook badStep;
    badStep.name = "Has bad step";
    PlaybookStep emptyStep;
    badStep.steps.push_back(emptyStep);
    CHECK_FALSE(engine.validatePlaybook(badStep));
}
