let currentScanReport = null;

document.addEventListener("DOMContentLoaded", () => {
    setupDragAndDrop();
    setupTabs();
    setupHelpModal();
});

// Setup Drag and Drop
function setupDragAndDrop() {
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("dragover");
        }, false);
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (fileInput.files.length > 0) {
            handleFileUpload(fileInput.files[0]);
        }
    });
}

// Setup Tabs Navigation
function setupTabs() {
    const tabButtons = document.querySelectorAll(".tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add("active");
            }
        });
    });
}

// Setup Help Modal
function setupHelpModal() {
    const btnHelp = document.getElementById("btnHelp");
    const helpModal = document.getElementById("helpModal");
    if (btnHelp && helpModal) {
        btnHelp.addEventListener("click", () => {
            helpModal.classList.add("show");
        });
    }
}

function closeHelpModal() {
    const helpModal = document.getElementById("helpModal");
    if (helpModal) {
        helpModal.classList.remove("show");
    }
}

// Upload & Scan File
async function handleFileUpload(file) {
    showLoading();
    animateLoadingSteps();

    const formData = new FormData();
    formData.append("file", file);
    const vtKey = document.getElementById("vtApiKey").value.trim();
    if (vtKey) {
        formData.append("vt_api_key", vtKey);
    }

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Quá trình quét thất bại.");
        }

        const data = await response.json();
        currentScanReport = data;
        hideLoading();
        displayResults(data);
    } catch (error) {
        hideLoading();
        alert("Lỗi: " + error.message);
    }
}

// Demo Scenarios
async function runDemoScan(sampleId) {
    showLoading();
    animateLoadingSteps();

    const vtKey = document.getElementById("vtApiKey").value.trim();
    try {
        const response = await fetch(`/api/demo-scan/${sampleId}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vt_api_key: vtKey })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || "Không thể tải kịch bản demo.");
        }

        const data = await response.json();
        currentScanReport = data;
        hideLoading();
        displayResults(data);
    } catch (error) {
        hideLoading();
        alert("Lỗi kịch bản demo: " + error.message);
    }
}

// Loading Steps Animation
function showLoading() {
    document.getElementById("scanLoading").style.display = "block";
    document.getElementById("resultsSection").style.display = "none";
}

function hideLoading() {
    document.getElementById("scanLoading").style.display = "none";
}

function animateLoadingSteps() {
    const steps = [
        { id: "step1", text: "1. Đang trích xuất PE Header, Entropy và đặc trưng tĩnh..." },
        { id: "step2", text: "2. Đang suy luận mô hình AI cục bộ & phân tích XAI..." },
        { id: "step3", text: "3. Đang tra cứu danh tiếng tri thức đám mây VirusTotal..." },
        { id: "step4", text: "4. Đang tổng hợp phán quyết lai và sinh kịch bản khắc phục..." }
    ];

    const statusEl = document.getElementById("loadingStatus");

    steps.forEach((step, idx) => {
        setTimeout(() => {
            steps.forEach(s => {
                const el = document.getElementById(s.id);
                if (el) el.classList.remove("active");
            });
            const currEl = document.getElementById(step.id);
            if (currEl) currEl.classList.add("active");
            if (statusEl) statusEl.innerText = step.text;
        }, idx * 450);
    });
}

// Render Results
function displayResults(data) {
    const resultsSection = document.getElementById("resultsSection");
    resultsSection.style.display = "block";
    resultsSection.scrollIntoView({ behavior: "smooth" });

    const verdict = data.hybrid_decision.final_verdict;
    const banner = document.getElementById("verdictBanner");
    const badge = document.getElementById("verdictBadge");
    const title = document.getElementById("verdictTitle");
    const rule = document.getElementById("verdictRule");
    const desc = document.getElementById("verdictExplanation");

    banner.className = "verdict-banner";
    badge.className = "verdict-badge";

    if (verdict === "MALICIOUS") {
        banner.classList.add("verdict-malicious");
        badge.classList.add("malicious");
        badge.innerText = "MALICIOUS (MÃ ĐỘC HẠI)";
        title.innerText = "PHÁT HIỆN TỆP CHỨA MÃ ĐỘC HẠI!";
    } else if (verdict === "SUSPICIOUS_UNKNOWN") {
        banner.classList.add("verdict-suspicious");
        badge.classList.add("suspicious");
        badge.innerText = "SUSPICIOUS (TỆP LẠ / NGHI VẤN)";
        title.innerText = "CẢNH BÁO: TỆP LẠ BẤT THƯỜNG / ZERO-DAY";
    } else {
        banner.classList.add("verdict-benign");
        badge.classList.add("benign");
        badge.innerText = "BENIGN (AN TOÀN)";
        title.innerText = "XÁC NHẬN: TỆP AN TOÀN, KHÔNG PHÁT HIỆN MÃ ĐỘC";
    }

    rule.innerText = `Quy tắc quyết định: ${data.hybrid_decision.applied_rule}`;
    desc.innerText = data.hybrid_decision.verdict_explanation;

    // Risk Meter Circle
    const riskScore = data.hybrid_decision.overall_risk_score;
    const riskPercent = Math.round(riskScore * 1000) / 10;
    document.getElementById("riskPercentage").innerText = `${riskPercent}%`;

    const circle = document.getElementById("riskRing");
    const circumference = 2 * Math.PI * 48; // ~301.59
    const offset = circumference - (riskScore * circumference);
    circle.style.strokeDashoffset = offset;

    if (verdict === "MALICIOUS") circle.setAttribute("stroke", "#ef4444");
    else if (verdict === "SUSPICIOUS_UNKNOWN") circle.setAttribute("stroke", "#f59e0b");
    else circle.setAttribute("stroke", "#10b981");

    // File Summary Info
    const fileInfo = data.file_info;
    document.getElementById("lblFilename").innerText = fileInfo.filename;
    document.getElementById("lblFileSize").innerText = formatBytes(fileInfo.file_size);
    document.getElementById("lblFormat").innerText = fileInfo.is_pe ? "Windows PE Executable" : "Dữ liệu nhị phân / Non-PE";
    document.getElementById("lblSha256").innerText = fileInfo.sha256;
    document.getElementById("lblImphash").innerText = fileInfo.imphash || "N/A";

    document.getElementById("lblSha256").onclick = () => {
        navigator.clipboard.writeText(fileInfo.sha256);
        alert("Đã sao chép SHA-256 vào bộ nhớ tạm: " + fileInfo.sha256);
    };

    // Render Tab 1: Remediation
    renderRemediationTab(data.remediation);

    // Render Tab 2: AI & XAI
    renderAITab(data.ai_analysis);

    // Render Tab 3: Cloud Threat Intel
    renderCloudTab(data.cloud_analysis);

    // Render Tab 4: Static Analysis
    renderStaticTab(data.static_analysis);
}

// Render Remediation Playbook
function renderRemediationTab(remed) {
    const sevBadge = document.getElementById("remedSeverity");
    sevBadge.innerText = remed.severity;
    sevBadge.style.background = `${remed.severity_color}25`;
    sevBadge.style.color = remed.severity_color;
    sevBadge.style.border = `1px solid ${remed.severity_color}`;

    // Threat categories tags
    const threatTagsWrap = document.getElementById("remedThreatTags");
    threatTagsWrap.innerHTML = "";
    (remed.detected_threat_categories || []).forEach(cat => {
        const span = document.createElement("span");
        span.className = "threat-tag-item";
        span.innerText = cat;
        threatTagsWrap.appendChild(span);
    });

    // Populate Steps
    populateActionList("listImmediate", remed.immediate_actions, "action", "detail");
    populateActionList("listInvestigation", remed.investigation_steps, "target", "detail");
    populateActionList("listEradication", remed.eradication_steps, "step", "detail");
    populateActionList("listHardening", remed.hardening_steps, "step", "detail");

    // PowerShell Script Preview
    document.getElementById("scriptCodeView").innerText = remed.powershell_script || "# Không có kịch bản xử lý.";
}

function populateActionList(containerId, list, titleKey, detailKey) {
    const container = document.getElementById(containerId);
    container.innerHTML = "";
    (list || []).forEach(item => {
        const div = document.createElement("div");
        div.className = "action-entry";
        div.innerHTML = `
            <strong>${item[titleKey]}</strong>
            <p>${item[detailKey]}</p>
        `;
        container.appendChild(div);
    });
}

// Render AI & Explainable AI
function renderAITab(ai) {
    const confPercent = Math.round(ai.ai_confidence * 1000) / 10;
    document.getElementById("aiConfVal").innerText = `${confPercent}%`;
    document.getElementById("aiConfBar").style.width = `${confPercent}%`;

    const badge = document.getElementById("aiClassBadge");
    badge.innerText = ai.ai_label;
    if (ai.ai_label === "MALICIOUS") {
        badge.style.background = "rgba(239, 68, 68, 0.2)";
        badge.style.color = "#ef4444";
    } else if (ai.ai_label === "SUSPICIOUS_UNKNOWN") {
        badge.style.background = "rgba(245, 158, 11, 0.2)";
        badge.style.color = "#f59e0b";
    } else {
        badge.style.background = "rgba(16, 185, 129, 0.2)";
        badge.style.color = "#10b981";
    }

    document.getElementById("aiClassDesc").innerText = ai.classification_desc;

    // XAI reasons
    const xaiList = document.getElementById("xaiReasonsList");
    xaiList.innerHTML = "";
    if (ai.xai_reasons && ai.xai_reasons.length > 0) {
        ai.xai_reasons.forEach(r => {
            const item = document.createElement("div");
            item.className = "xai-item";
            item.innerHTML = `
                <div class="xai-item-head">
                    <span class="xai-sev ${r.severity}">${r.severity}</span>
                    <span class="xai-tag">${r.tag}</span>
                </div>
                <div class="xai-desc">${r.detail}</div>
            `;
            xaiList.appendChild(item);
        });
    } else {
        xaiList.innerHTML = `<div class="xai-desc" style="color: #10b981;">Không phát hiện bất thường đáng ngờ nào trong cấu trúc nhị phân và hàm gọi API.</div>`;
    }
}

// Render Cloud Threat Intel
function renderCloudTab(cloud) {
    document.getElementById("cloudPositives").innerText = `${cloud.positives}/${cloud.total}`;
    document.getElementById("cloudThreatName").innerText = cloud.threat_classification || "Không xác định";
    document.getElementById("cloudSource").innerText = `Nguồn: ${cloud.source || "VirusTotal"}`;

    const avGrid = document.getElementById("avDetectionsGrid");
    avGrid.innerHTML = "";
    const detections = cloud.top_detections || {};
    const entries = Object.entries(detections);

    if (entries.length > 0) {
        entries.forEach(([vendor, res]) => {
            const card = document.createElement("div");
            card.className = "av-card";
            card.innerHTML = `
                <span class="av-name">${vendor}</span>
                <span class="av-result">${res}</span>
            `;
            avGrid.appendChild(card);
        });
    } else {
        avGrid.innerHTML = `<p style="color: #94a3b8; font-size: 0.85rem;">Chưa có cảnh báo từ các hãng AV hàng đầu hoặc file chưa có trên cơ sở dữ liệu đám mây.</p>`;
    }
}

// Render Static Analysis
function renderStaticTab(stat) {
    document.getElementById("staticOverallEntropy").innerText = `${stat.overall_entropy} / 8.0`;
    document.getElementById("staticMaxSecEntropy").innerText = `${stat.max_section_entropy} / 8.0`;
    document.getElementById("staticNumSections").innerText = stat.num_sections;
    document.getElementById("staticNumImports").innerText = `${stat.num_imported_dlls} DLLs / ${stat.num_imported_funcs} APIs`;

    // Sections Table
    const tbody = document.getElementById("sectionsTableBody");
    tbody.innerHTML = "";
    (stat.sections || []).forEach(sec => {
        const tr = document.createElement("tr");
        if (sec.is_suspicious) tr.className = "suspicious-row";
        tr.innerHTML = `
            <td><strong class="mono" style="color: ${sec.is_suspicious ? '#ef4444' : '#fff'}">${sec.name}</strong></td>
            <td class="mono">${formatBytes(sec.virtual_size)}</td>
            <td class="mono">${formatBytes(sec.raw_size)}</td>
            <td class="mono" style="color: ${sec.entropy > 7.0 ? '#ef4444' : '#38bdf8'}">${sec.entropy}</td>
            <td>
                <span class="badge-status ${sec.is_suspicious ? 'suspect' : 'normal'}">
                    ${sec.is_suspicious ? 'BẤT THƯỜNG / NÉN' : 'BÌNH THƯỜNG'}
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Suspicious API Categories
    const apiGrid = document.getElementById("apiCategoriesGrid");
    apiGrid.innerHTML = "";
    const apis = stat.suspicious_apis || {};

    const categoryTitles = {
        injection: "Process Injection & Memory (Tiêm mã bộ nhớ)",
        persistence: "Persistence (Duy trì khởi động / Registry / Service)",
        evasion: "Anti-Analysis & Evasion (Chống dịch ngược / Lẩn tránh)",
        network: "Network C2 / Dropper (Tải tệp & Kết nối mạng)",
        execution: "Execution (Thực thi lệnh ẩn)",
        spying: "Information Stealing (Theo dõi bàn phím / Dữ liệu)"
    };

    Object.entries(categoryTitles).forEach(([catKey, title]) => {
        const card = document.createElement("div");
        card.className = "api-cat-card";
        const funcs = apis[catKey] || [];
        card.innerHTML = `
            <div class="api-cat-title">${title} (${funcs.length})</div>
            <div class="api-chips">
                ${funcs.length > 0 
                    ? funcs.map(f => `<span class="api-chip threat">${f}</span>`).join("") 
                    : `<span class="api-chip" style="color: #64748b;">Không phát hiện</span>`
                }
            </div>
        `;
        apiGrid.appendChild(card);
    });
}

// Copy & Download Script
function copyPowerShellScript() {
    if (!currentScanReport || !currentScanReport.remediation) return;
    const script = currentScanReport.remediation.powershell_script;
    navigator.clipboard.writeText(script);
    alert("Đã sao chép kịch bản PowerShell vào Clipboard!");
}

function downloadPowerShellScript() {
    if (!currentScanReport || !currentScanReport.remediation) return;
    const script = currentScanReport.remediation.powershell_script;
    const filename = `remediate_${currentScanReport.file_info.filename}.ps1`;

    fetch("/api/download-script", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ script: script, filename: filename })
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
    });
}

// Reset Scanner
function resetScanner() {
    document.getElementById("resultsSection").style.display = "none";
    document.getElementById("dropZone").scrollIntoView({ behavior: "smooth" });
}

// Helper: Format Bytes
function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}
