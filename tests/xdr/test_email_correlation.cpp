#include <doctest/doctest.h>
#include <xdr/EmailCorrelation.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("EmailCorrelation - Submit email event") {
    EmailCorrelation ec;

    EmailEvent event;
    event.sender = "attacker@evil.com";
    event.recipient = "user@company.com";
    event.subject = "Urgent: Reset Password";
    event.eventType = "phishing";
    event.severity = "high";
    event.timestamp = "2024-01-15T10:00:00";

    std::string id = ec.submitEmailEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(ec.getEventCount() == 1);
}

TEST_CASE("EmailCorrelation - Detect phishing campaigns") {
    EmailCorrelation ec;

    // Same sender domain, multiple phishing emails
    for (int i = 0; i < 3; i++) {
        EmailEvent event;
        event.sender = "phisher" + std::to_string(i) + "@evil-domain.com";
        event.recipient = "user" + std::to_string(i) + "@company.com";
        event.subject = "Urgent action required";
        event.eventType = "phishing";
        event.severity = "high";
        ec.submitEmailEvent(event);
    }

    auto campaigns = ec.detectPhishingCampaigns();
    REQUIRE_FALSE(campaigns.empty());
    CHECK(campaigns[0].senderDomain == "evil-domain.com");
    CHECK(campaigns[0].emailCount >= 3);
    CHECK(campaigns[0].targetedUsers.size() == 3);
}

TEST_CASE("EmailCorrelation - No campaign from single email") {
    EmailCorrelation ec;

    EmailEvent event;
    event.sender = "attacker@evil.com";
    event.recipient = "user@company.com";
    event.eventType = "phishing";
    ec.submitEmailEvent(event);

    auto campaigns = ec.detectPhishingCampaigns();
    CHECK(campaigns.empty());
}

TEST_CASE("EmailCorrelation - Link email to endpoint") {
    EmailCorrelation ec;

    EmailEvent email;
    email.sender = "attacker@evil.com";
    email.recipient = "user@company.com";
    email.eventType = "phishing";
    std::string emailId = ec.submitEmailEvent(email);

    EmailEndpointLink link;
    link.emailEventId = emailId;
    link.endpointEventId = "EPT-001";
    link.linkType = "attachment_executed";
    link.timestamp = "2024-01-15T10:05:00";
    ec.linkEmailToEndpoint(link);

    auto links = ec.getEndpointLinks(emailId);
    REQUIRE(links.size() == 1);
    CHECK(links[0].linkType == "attachment_executed");
    CHECK(links[0].endpointEventId == "EPT-001");
}

TEST_CASE("EmailCorrelation - Get suspicious senders") {
    EmailCorrelation ec;

    EmailEvent e1;
    e1.sender = "phisher@evil.com";
    e1.eventType = "phishing";
    ec.submitEmailEvent(e1);

    EmailEvent e2;
    e2.sender = "normal@company.com";
    e2.eventType = "spam";
    ec.submitEmailEvent(e2);

    EmailEvent e3;
    e3.sender = "attacker@malware.org";
    e3.eventType = "malicious_attachment";
    ec.submitEmailEvent(e3);

    auto senders = ec.getSuspiciousSenders();
    CHECK(senders.size() == 2);
}

TEST_CASE("EmailCorrelation - Get malicious URLs") {
    EmailCorrelation ec;

    EmailEvent event;
    event.sender = "attacker@evil.com";
    event.eventType = "suspicious_link";
    event.urls = {"http://malware.com/payload", "http://evil.org/phish"};
    ec.submitEmailEvent(event);

    auto urls = ec.getMaliciousURLs();
    CHECK(urls.size() == 2);
}

TEST_CASE("EmailCorrelation - Phishing count") {
    EmailCorrelation ec;

    EmailEvent e1;
    e1.sender = "a@evil.com";
    e1.eventType = "phishing";
    ec.submitEmailEvent(e1);

    EmailEvent e2;
    e2.sender = "b@evil.com";
    e2.eventType = "spam";
    ec.submitEmailEvent(e2);

    EmailEvent e3;
    e3.sender = "c@evil.com";
    e3.eventType = "phishing";
    ec.submitEmailEvent(e3);

    CHECK(ec.getPhishingCount() == 2);
    CHECK(ec.getEventCount() == 3);
}
