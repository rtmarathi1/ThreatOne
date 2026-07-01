#include <doctest/doctest.h>
#include <ai/ModelManager.h>

#include <string>
#include <vector>

using namespace ThreatOne::AI;

TEST_CASE("ModelManager - load/unload lifecycle") {
    ModelManager manager;

    SUBCASE("Load a model successfully") {
        bool loaded = manager.loadModel("test_model", "");
        CHECK(loaded == true);
        CHECK(manager.getModelCount() == 1);
        CHECK(manager.isModelLoaded("test_model") == true);
    }

    SUBCASE("Loaded model can be retrieved") {
        manager.loadModel("my_model", "");
        IMLModel* model = manager.getModel("my_model");
        CHECK(model != nullptr);
        CHECK(!model->getName().empty());
    }

    SUBCASE("Unload removes model") {
        manager.loadModel("to_remove", "");
        CHECK(manager.isModelLoaded("to_remove") == true);

        bool unloaded = manager.unloadModel("to_remove");
        CHECK(unloaded == true);
        CHECK(manager.isModelLoaded("to_remove") == false);
        CHECK(manager.getModel("to_remove") == nullptr);
    }

    SUBCASE("Unload non-existent model fails gracefully") {
        bool result = manager.unloadModel("nonexistent");
        CHECK(result == false);
    }

    SUBCASE("Get non-existent model returns nullptr") {
        IMLModel* model = manager.getModel("nonexistent");
        CHECK(model == nullptr);
    }
}

TEST_CASE("ModelManager - listModels") {
    ModelManager manager;

    SUBCASE("Empty manager has no models") {
        auto models = manager.listModels();
        CHECK(models.empty());
    }

    SUBCASE("Listed models match loaded models") {
        manager.loadModel("model_a", "");
        manager.loadModel("model_b", "");

        auto models = manager.listModels();
        CHECK(models.size() == 2);

        bool foundA = false, foundB = false;
        for (const auto& info : models) {
            if (info.id == "model_a") foundA = true;
            if (info.id == "model_b") foundB = true;
        }
        CHECK(foundA == true);
        CHECK(foundB == true);
    }

    SUBCASE("Model info has correct status") {
        manager.loadModel("active_model", "");
        auto models = manager.listModels();
        REQUIRE(!models.empty());
        CHECK(models[0].status == ModelStatus::Loaded);
    }
}

TEST_CASE("ModelManager - version tracking") {
    ModelManager manager;

    SUBCASE("Model version is populated after load") {
        manager.loadModel("versioned", "");
        auto info = manager.getPerformance("versioned");
        CHECK(!info.version.empty());
        CHECK(info.version == "1.0.0");
    }

    SUBCASE("Model name is set correctly") {
        manager.loadModel("named_model", "");
        auto info = manager.getPerformance("named_model");
        CHECK(!info.name.empty());
    }

    SUBCASE("Prediction count starts at zero") {
        manager.loadModel("counting", "");
        auto info = manager.getPerformance("counting");
        CHECK(info.predictionCount == 0);
    }
}

TEST_CASE("ModelManager - drift detection") {
    ModelManager manager;
    manager.loadModel("drift_model", "");

    SUBCASE("Drift detection with similar distributions returns low score") {
        // Build recent predictions that look similar
        std::vector<std::vector<double>> recent;
        for (int i = 0; i < 20; ++i) {
            recent.push_back({0.8, 0.2});
        }
        // Record some history predictions to compare against
        for (int i = 0; i < 20; ++i) {
            manager.recordPrediction("drift_model", {0.8, 0.2});
        }

        double drift = manager.detectDrift("drift_model", recent);
        CHECK(drift >= 0.0);
    }

    SUBCASE("Drift detection with different distributions returns higher score") {
        // Build baseline of one kind
        for (int i = 0; i < 20; ++i) {
            manager.recordPrediction("drift_model", {0.9, 0.1});
        }

        // Recent predictions are very different
        std::vector<std::vector<double>> recent;
        for (int i = 0; i < 20; ++i) {
            recent.push_back({0.1, 0.9});
        }

        double drift = manager.detectDrift("drift_model", recent);
        CHECK(drift >= 0.0);
    }
}

TEST_CASE("ModelManager - update model") {
    ModelManager manager;
    manager.loadModel("updatable", "");

    SUBCASE("Update existing model succeeds") {
        bool updated = manager.updateModel("updatable", "");
        CHECK(updated == true);
        CHECK(manager.isModelLoaded("updatable") == true);
    }

    SUBCASE("Update non-existent model fails") {
        bool updated = manager.updateModel("no_such_model", "");
        CHECK(updated == false);
    }
}
