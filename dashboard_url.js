/**
 * ThreatLens Dashboard Controller
 * Connects Dashboard with FastAPI Backend
 */

document.addEventListener("DOMContentLoaded", () => {

    console.log("ThreatLens Dashboard Loaded");

    // -------------------------
    // DOM Elements
    // -------------------------

    const riskRing = document.getElementById("risk-ring");
    const riskPercent = document.getElementById("risk-percent");
    const verdictBadge = document.getElementById("verdict-text");
    const targetUrlText = document.getElementById("target-url");

    if (!riskRing || !riskPercent || !verdictBadge || !targetUrlText) {
        console.error("Some required HTML elements are missing.");
        return;
    }

    // -------------------------
    // Get URL Parameter
    // -------------------------

    const params = new URLSearchParams(window.location.search);
    let targetUrl = params.get("url");

    // Default URL for testing
    if (!targetUrl) {
        targetUrl = "https://www.google.com";
        console.warn("No URL passed. Using test URL:", targetUrl);
    }

    targetUrlText.textContent = targetUrl;

    // -------------------------
    // Ring Setup
    // -------------------------

    const radius = riskRing.r.baseVal.value;
    const circumference = 2 * Math.PI * radius;

    riskRing.style.strokeDasharray = circumference;
    riskRing.style.strokeDashoffset = circumference;

    function updateRing(score) {

        const offset =
            circumference - (score / 100) * circumference;

        riskRing.style.strokeDashoffset = offset;

        riskPercent.textContent = `${Math.round(score)}%`;

        riskRing.classList.remove(
            "ring-safe",
            "ring-warning",
            "ring-danger"
        );

        if (score < 40)
            riskRing.classList.add("ring-safe");
        else if (score < 75)
            riskRing.classList.add("ring-warning");
        else
            riskRing.classList.add("ring-danger");
    }

    // -------------------------
    // Update Feature
    // -------------------------

    function updateFeature(name, value) {

        const el = document.getElementById(`feat-${name}`);

        if (!el) return;

        if (
            typeof value === "number" &&
            !Number.isInteger(value)
        ) {
            el.textContent = value.toFixed(2);
        }
        else {
            el.textContent = value;
        }

    }

    // -------------------------
    // Call Backend
    // -------------------------

    async function analyzeURL() {

        try {

            verdictBadge.textContent = "Scanning...";
            verdictBadge.className =
                "verdict-badge status-loading";

            console.log("Sending request...");

            const response = await fetch(
                "http://127.0.0.1:8000/analyze",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        url: targetUrl
                    })
                }
            );

            console.log("Status:", response.status);

            if (!response.ok) {

                const error = await response.text();

                console.error(error);

                throw new Error(error);

            }

            const data = await response.json();
            await scanDomainIntelligence(targetUrl);

            console.log("Backend Response:", data);

            verdictBadge.textContent = data.verdict;

            verdictBadge.className =
                `verdict-badge status-${data.status_class}`;

            updateRing(data.risk_percentage);

            const features = data.extracted_features;

            for (const key in features) {

                updateFeature(key, features[key]);

            }

        }

        catch (err) {

            console.error("ERROR:", err);

            verdictBadge.textContent = "Backend Offline";

            verdictBadge.className =
                "verdict-badge status-danger";

            riskPercent.textContent = "--%";

        }

    }

    analyzeURL();

});

// Function that sends the domain to your Python backend
async function scanDomainIntelligence(domainName) {
console.log("scanDomainIntelligence called with:", domainName);
    const API_URL =
        `http://127.0.0.1:8000/api/analyze-domain?url=${encodeURIComponent(domainName)}`;

    try {

        const response = await fetch(API_URL);
        const data = await response.json();
        console.log("Domain API Response:", data);

        document.getElementById("domain-whois").textContent = data.whoisStatus;
        document.getElementById("domain-age").textContent = data.age;
        document.getElementById("domain-registrar").textContent = data.registrar;
        document.getElementById("domain-expiry").textContent = data.expirationDate;
        document.getElementById("domain-dns").textContent = `${data.dnsRecordCount} Found`;
        document.getElementById("domain-ip").textContent = data.ipAddress;

        const sslElement = document.getElementById("domain-ssl");

        if (data.sslValid) {
            sslElement.textContent = "Valid";
            sslElement.style.color = "#10B981";
        } else {
            sslElement.textContent = "Invalid / None";
            sslElement.style.color = "#EF4444";
        }

    } catch (error) {

        console.error("Error communicating with Python scanning engine:", error);

    }
}