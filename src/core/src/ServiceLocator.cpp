#include "core/ServiceLocator.h"
#include <mutex>
#include <shared_mutex>

namespace ThreatOne::Core {

ServiceLocator& ServiceLocator::instance() {
    static ServiceLocator instance;
    return instance;
}

void ServiceLocator::clear() {
    std::unique_lock lock(mutex_);
    services_.clear();
}

size_t ServiceLocator::serviceCount() const {
    std::shared_lock lock(mutex_);
    return services_.size();
}

} // namespace ThreatOne::Core
