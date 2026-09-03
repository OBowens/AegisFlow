document.addEventListener("DOMContentLoaded", function () {
    var storageKey = "aegisflow-dashboard-theme";
    var root = document.documentElement;
    var body = document.body;
    var themeToggle = document.querySelector("[data-theme-toggle]");
    var sidebarToggle = document.querySelector("[data-sidebar-toggle]");
    var sidebarOverlay = document.querySelector("[data-sidebar-overlay]");
    var banner = document.querySelector("[data-preparedness-banner]");
    var bannerClose = document.querySelector("[data-preparedness-close]");
    var refreshButton = document.querySelector("[data-dashboard-refresh]");
    var fileInput = document.querySelector("[data-file-input]");
    var dropzone = document.querySelector("[data-dropzone]");
    var selectedUploadsContainer = document.querySelector("[data-selected-uploads]");
    var uploadEmptyState = document.querySelector("[data-upload-empty]");
    var sourceTypeSelect = document.querySelector("[data-source-type-select]");
    var notesField = document.querySelector("[data-notes-field]");
    var notesCount = document.querySelector("[data-notes-count]");
    var sourceCards = document.querySelectorAll("[data-source-card]");

    function applyTheme(theme) {
        var nextTheme = theme === "dark" ? "dark" : "light";
        root.dataset.theme = nextTheme;

        if (themeToggle) {
            themeToggle.setAttribute(
                "aria-label",
                nextTheme === "dark" ? "Switch to light mode" : "Switch to dark mode"
            );
        }

        try {
            localStorage.setItem(storageKey, nextTheme);
        } catch (error) {
            return;
        }
    }

    function isMobileViewport() {
        return window.innerWidth <= 991;
    }

    function syncSidebarState() {
        if (!sidebarToggle) {
            return;
        }

        if (isMobileViewport()) {
            sidebarToggle.setAttribute("aria-expanded", body.classList.contains("sidebar-open") ? "true" : "false");
        } else {
            sidebarToggle.setAttribute("aria-expanded", body.classList.contains("sidebar-collapsed") ? "false" : "true");
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener("click", function () {
            var nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
            applyTheme(nextTheme);
        });
    }

    if (sidebarToggle) {
        sidebarToggle.addEventListener("click", function () {
            if (isMobileViewport()) {
                body.classList.toggle("sidebar-open");
            } else {
                body.classList.toggle("sidebar-collapsed");
            }

            syncSidebarState();
        });
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener("click", function () {
            body.classList.remove("sidebar-open");
            syncSidebarState();
        });
    }

    if (banner && bannerClose) {
        bannerClose.addEventListener("click", function () {
            banner.classList.add("is-hidden");
        });
    }

    if (refreshButton) {
        refreshButton.addEventListener("click", function () {
            window.location.reload();
        });
    }

    function syncUploadSourceCards() {
        if (!sourceTypeSelect || !sourceCards.length) { return; }
        sourceCards.forEach(function (card) {
            var selected = card.dataset.sourceValue === sourceTypeSelect.value;
            card.classList.toggle("is-selected", selected);
            card.setAttribute("aria-pressed", selected ? "true" : "false");
        });
    }

    if (sourceTypeSelect && sourceCards.length) {
        sourceCards.forEach(function (card) {
            card.addEventListener("click", function () {
                sourceTypeSelect.value = card.dataset.sourceValue;
                sourceTypeSelect.dispatchEvent(new Event("change", { bubbles: true }));
            });
        });
        sourceTypeSelect.addEventListener("change", syncUploadSourceCards);
        sourceTypeSelect.form.addEventListener("reset", function () {
            window.setTimeout(function () {
                syncUploadSourceCards();
                if (fileInput) { fileInput.dispatchEvent(new Event("change", { bubbles: true })); }
                if (notesCount) { notesCount.textContent = "0"; }
            }, 0);
        });
        syncUploadSourceCards();
    }

    var readinessQuestionInput = document.querySelector("[data-readiness-question-input]");
    var readinessExampleChips = document.querySelectorAll("[data-readiness-example-chip]");

    if (readinessQuestionInput && readinessExampleChips.length) {
        readinessExampleChips.forEach(function (chip) {
            chip.addEventListener("click", function () {
                readinessQuestionInput.value = chip.textContent.trim();
                readinessQuestionInput.focus();
            });
        });
    }

    function formatBytes(bytes) {
        if (!bytes && bytes !== 0) {
            return "Unknown size";
        }

        if (bytes < 1024) {
            return bytes + " bytes";
        }

        var units = ["KB", "MB", "GB"];
        var value = bytes;
        var unitIndex = -1;

        do {
            value = value / 1024;
            unitIndex += 1;
        } while (value >= 1024 && unitIndex < units.length - 1);

        return value.toFixed(value >= 10 ? 0 : 1) + " " + units[unitIndex];
    }

    function badgeToneForFile(name) {
        var suffix = "";
        var lastDot = name.lastIndexOf(".");

        if (lastDot !== -1) {
            suffix = name.slice(lastDot).toLowerCase();
        }

        if (suffix === ".json" || suffix === ".jsonl") {
            return "upload-file-badge--blue";
        }
        if (suffix === ".csv") {
            return "upload-file-badge--green";
        }
        if (suffix === ".log") {
            return "upload-file-badge--amber";
        }
        if (suffix === ".txt") {
            return "upload-file-badge--teal";
        }
        return "upload-file-badge--slate";
    }

    // Mirrors apps/log_intake/services/sniffer.py's structural signals --
    // keep the two in sync if a parser's distinguishing fields change.
    var SSHD_LINE_RE = /^(\S+)\s+(\S+)\s+([\w.\-()]+)(?:\[(\d+)\])?:\s?(.*)$/;
    var PRTG_HEADER_SIGNAL = ["sensor", "status", "device"];
    var SSL_HEADER_SIGNAL = ["hostname", "common_name", "days_remaining"];
    var SNIFF_SAMPLE_LINE_COUNT = 10;

    function sniffSourceType(rawText) {
        if (!rawText || !rawText.trim()) {
            return null;
        }

        return sniffCsv(rawText) || sniffJsonLines(rawText) || (sniffLinuxAuth(rawText) ? "linux" : null);
    }

    function sniffCsv(rawText) {
        var firstLine = rawText.split(/\r?\n/)[0] || "";
        if (firstLine.indexOf(",") === -1) {
            return null;
        }

        var header = {};
        firstLine.split(",").forEach(function (cell) {
            header[cell.trim().toLowerCase()] = true;
        });

        if (PRTG_HEADER_SIGNAL.every(function (key) { return header[key]; })) {
            return "prtg";
        }
        if (SSL_HEADER_SIGNAL.every(function (key) { return header[key]; })) {
            return "ssl_certificate";
        }

        return null;
    }

    function sniffJsonLines(rawText) {
        var lines = rawText.split(/\r?\n/).slice(0, SNIFF_SAMPLE_LINE_COUNT);
        var votes = {};

        lines.forEach(function (line) {
            line = line.trim();
            if (!line) {
                return;
            }

            var record;
            try {
                record = JSON.parse(line);
            } catch (error) {
                return;
            }

            if (!record || typeof record !== "object" || Array.isArray(record)) {
                return;
            }

            var guess = classifyJsonRecord(record);
            if (guess) {
                votes[guess] = (votes[guess] || 0) + 1;
            }
        });

        var best = null;
        var bestCount = 0;
        Object.keys(votes).forEach(function (key) {
            if (votes[key] > bestCount) {
                best = key;
                bestCount = votes[key];
            }
        });

        return best;
    }

    function classifyJsonRecord(record) {
        if (record.rule && typeof record.rule === "object" && record.agent && typeof record.agent === "object") {
            return "wazuh";
        }
        if (typeof record.EventID === "number" && Object.prototype.hasOwnProperty.call(record, "Computer")) {
            return "windows";
        }
        if (
            Object.prototype.hasOwnProperty.call(record, "facility") &&
            Object.prototype.hasOwnProperty.call(record, "message")
        ) {
            return "graylog";
        }
        return null;
    }

    function sniffLinuxAuth(rawText) {
        var lines = rawText.split(/\r?\n/);
        var checked = 0;

        for (var i = 0; i < lines.length; i += 1) {
            var line = lines[i].trim();
            if (!line) {
                continue;
            }

            checked += 1;
            if (checked > SNIFF_SAMPLE_LINE_COUNT) {
                break;
            }

            var match = SSHD_LINE_RE.exec(line);
            if (match && match[3] === "sshd" && match[4]) {
                return true;
            }
        }

        return false;
    }

    function readFileAsText(file) {
        return new Promise(function (resolve) {
            var reader = new FileReader();
            reader.onload = function () {
                resolve(typeof reader.result === "string" ? reader.result : "");
            };
            reader.onerror = function () {
                resolve("");
            };
            reader.readAsText(file);
        });
    }

    function detectAndPreselectSourceType() {
        if (!fileInput || !sourceTypeSelect) {
            return;
        }

        var files = fileInput.files;
        if (!files || !files.length) {
            return;
        }

        var reads = [];
        for (var i = 0; i < files.length; i += 1) {
            reads.push(readFileAsText(files[i]));
        }

        Promise.all(reads).then(function (contents) {
            var votes = {};
            contents.forEach(function (text) {
                var guess = sniffSourceType(text);
                if (guess) {
                    votes[guess] = (votes[guess] || 0) + 1;
                }
            });

            var best = null;
            var bestCount = 0;
            Object.keys(votes).forEach(function (key) {
                if (votes[key] > bestCount) {
                    best = key;
                    bestCount = votes[key];
                }
            });

            if (best && sourceTypeSelect.querySelector('option[value="' + best + '"]')) {
                sourceTypeSelect.value = best;
            }
        });
    }

    function removeSelectedFile(index) {
        if (!fileInput || !fileInput.files || typeof DataTransfer === "undefined") {
            return;
        }

        var dataTransfer = new DataTransfer();
        var files = fileInput.files;
        for (var i = 0; i < files.length; i += 1) {
            if (i !== index) {
                dataTransfer.items.add(files[i]);
            }
        }

        fileInput.files = dataTransfer.files;
        updateSelectedUploadPreview();
        detectAndPreselectSourceType();
    }

    function buildSelectedFileRow(file, index) {
        var fileName = file.name || "Selected file";
        var badge = "FILE";
        var lastDot = fileName.lastIndexOf(".");
        if (lastDot !== -1) {
            badge = fileName.slice(lastDot + 1).toUpperCase().slice(0, 4);
        }

        var row = document.createElement("article");
        row.className = "upload-file-row upload-file-row--preview";

        var main = document.createElement("div");
        main.className = "upload-file-row__main";

        var badgeEl = document.createElement("div");
        badgeEl.className = "upload-file-badge " + badgeToneForFile(fileName);
        badgeEl.textContent = badge;

        var copy = document.createElement("div");
        copy.className = "upload-file-copy";

        var nameEl = document.createElement("h3");
        nameEl.textContent = fileName;

        var metaEl = document.createElement("p");
        metaEl.textContent =
            formatBytes(file.size) + " • File selected — click Analyze Logs below to upload.";

        copy.appendChild(nameEl);
        copy.appendChild(metaEl);
        main.appendChild(badgeEl);
        main.appendChild(copy);

        var status = document.createElement("div");
        status.className = "upload-file-row__status upload-file-row__status--warning";

        var statusLine = document.createElement("div");
        statusLine.className = "upload-file-row__status-line";

        var dot = document.createElement("span");
        dot.className = "upload-status-dot";

        var strong = document.createElement("strong");
        strong.textContent = "Ready";

        statusLine.appendChild(dot);
        statusLine.appendChild(strong);

        var small = document.createElement("small");
        small.textContent = "Queued for upload";

        status.appendChild(statusLine);
        status.appendChild(small);

        var removeButton = document.createElement("button");
        removeButton.type = "button";
        removeButton.className = "upload-file-row__remove";
        removeButton.setAttribute("aria-label", "Remove " + fileName + " from the upload");
        removeButton.innerHTML = '<svg class="icon"><use href="#icon-close"></use></svg>';
        removeButton.addEventListener("click", function () {
            removeSelectedFile(index);
        });

        row.appendChild(main);
        row.appendChild(status);
        row.appendChild(removeButton);

        return row;
    }

    function updateSelectedUploadPreview() {
        if (!fileInput || !selectedUploadsContainer) {
            return;
        }

        selectedUploadsContainer.innerHTML = "";

        var files = fileInput.files;
        if (!files || !files.length) {
            selectedUploadsContainer.classList.add("is-hidden");
            if (uploadEmptyState) {
                uploadEmptyState.classList.remove("is-hidden");
            }
            return;
        }

        for (var i = 0; i < files.length; i += 1) {
            selectedUploadsContainer.appendChild(buildSelectedFileRow(files[i], i));
        }

        selectedUploadsContainer.classList.remove("is-hidden");

        if (uploadEmptyState) {
            uploadEmptyState.classList.add("is-hidden");
        }
    }

    function syncNotesCount() {
        if (!notesField || !notesCount) {
            return;
        }

        notesCount.textContent = String(notesField.value.length);
    }

    if (fileInput) {
        fileInput.addEventListener("change", updateSelectedUploadPreview);
        fileInput.addEventListener("change", detectAndPreselectSourceType);
        updateSelectedUploadPreview();
    }

    if (dropzone) {
        ["dragenter", "dragover"].forEach(function (eventName) {
            dropzone.addEventListener(eventName, function (event) {
                event.preventDefault();
                dropzone.classList.add("is-dragover");
            });
        });

        ["dragleave", "drop"].forEach(function (eventName) {
            dropzone.addEventListener(eventName, function (event) {
                event.preventDefault();
                dropzone.classList.remove("is-dragover");

                if (eventName !== "drop" || !fileInput) {
                    return;
                }

                var droppedFiles = event.dataTransfer && event.dataTransfer.files;
                if (!droppedFiles || !droppedFiles.length) {
                    return;
                }

                fileInput.files = droppedFiles;
                updateSelectedUploadPreview();
                detectAndPreselectSourceType();
            });
        });
    }

    if (notesField) {
        notesField.addEventListener("input", syncNotesCount);
        syncNotesCount();
    }

    document.querySelectorAll("[data-delete-upload-form]").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            var message =
                form.getAttribute("data-confirm-message") || "Delete this upload? This cannot be undone.";
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

    document.querySelectorAll("[data-tabs]").forEach(function (tabNav) {
        var buttons = tabNav.querySelectorAll("[data-tab-target]");
        var panels = tabNav.parentElement.querySelectorAll("[data-tab-panel]");

        buttons.forEach(function (button) {
            button.addEventListener("click", function () {
                var target = button.getAttribute("data-tab-target");

                buttons.forEach(function (otherButton) {
                    var isActive = otherButton === button;
                    otherButton.classList.toggle("is-active", isActive);
                    otherButton.setAttribute("aria-selected", isActive ? "true" : "false");
                });

                panels.forEach(function (panel) {
                    panel.hidden = panel.getAttribute("data-tab-panel") !== target;
                });
            });
        });
    });

    document.querySelectorAll("[data-auto-submit]").forEach(function (control) {
        control.addEventListener("change", function () {
            if (control.form) {
                control.form.submit();
            }
        });
    });

    window.addEventListener("resize", function () {
        if (!isMobileViewport()) {
            body.classList.remove("sidebar-open");
        }

        syncSidebarState();
    });

    applyTheme(root.dataset.theme);
    syncSidebarState();
});


// Presentation-only experience switch. It never changes roles or permissions.
(function () {
    var root = document.documentElement;
    var menu = document.querySelector("[data-profile-menu]");
    var trigger = document.querySelector("[data-profile-trigger]");
    var panel = document.querySelector("[data-profile-panel]");
    var choices = document.querySelectorAll("[data-experience-choice]");

    function applyExperience(mode) {
        var next = mode === "soc" ? "soc" : "business";
        root.dataset.experience = next;
        choices.forEach(function (choice) {
            var active = choice.dataset.experienceChoice === next;
            choice.classList.toggle("is-active", active);
            if (choice.getAttribute("role") === "radio") {
                choice.setAttribute("aria-checked", active ? "true" : "false");
            }
        });
        document.querySelectorAll("[data-active-mode-label]").forEach(function (label) {
            label.textContent = next === "soc" ? "SOC Mode" : "Business Mode";
        });
        try { localStorage.setItem("aegisflow-experience-mode", next); } catch (error) {}

        var persistence = Promise.resolve();
        if (menu && menu.dataset.experienceUrl) {
            var tokenField = menu.querySelector("[data-experience-form] input[name=csrfmiddlewaretoken]");
            var data = new FormData();
            data.append("mode", next);
            persistence = fetch(menu.dataset.experienceUrl, {
                method: "POST",
                headers: tokenField ? { "X-CSRFToken": tokenField.value } : {},
                body: data,
                credentials: "same-origin"
            }).catch(function () {});
        }
        document.dispatchEvent(new CustomEvent("aegisflow:experience", { detail: { mode: next } }));
        return persistence;
    }

    applyExperience(root.dataset.experience || "soc");
    if (trigger && panel) {
        trigger.addEventListener("click", function () {
            var open = panel.hidden;
            panel.hidden = !open;
            trigger.setAttribute("aria-expanded", String(open));
        });
    }
    choices.forEach(function (choice) {
        choice.addEventListener("click", function () {
            var saved = applyExperience(choice.dataset.experienceChoice);
            if (panel) panel.hidden = true;
            saved.finally(function () { window.location.reload(); });
        });
    });
    document.addEventListener("click", function (event) {
        if (menu && panel && !menu.contains(event.target)) panel.hidden = true;
    });
}());
var settingsThemeToggle = document.querySelector("[data-settings-theme-toggle]");
if (settingsThemeToggle) settingsThemeToggle.addEventListener("click", function () {
    var globalThemeToggle = document.querySelector(".icon-button--theme[data-theme-toggle]");
    if (globalThemeToggle) globalThemeToggle.click();
});

// Functional top-bar notification and help popovers.
document.querySelectorAll("[data-popover]").forEach(function (menu) {
    var trigger = menu.querySelector("[data-popover-trigger]");
    var panel = menu.querySelector("[data-popover-panel]");
    if (!trigger || !panel) return;
    trigger.addEventListener("click", function (event) {
        event.stopPropagation();
        document.querySelectorAll("[data-popover-panel]").forEach(function (other) { if (other !== panel) other.hidden = true; });
        panel.hidden = !panel.hidden;
    });
});
document.addEventListener("click", function (event) {
    document.querySelectorAll("[data-popover]").forEach(function (menu) {
        if (!menu.contains(event.target)) { var panel = menu.querySelector("[data-popover-panel]"); if (panel) panel.hidden = true; }
    });
});

// Work Queue overview modal.
(function () {
    var openButton = document.querySelector("[data-queue-overview-open]");
    var modal = document.querySelector("[data-queue-overview-modal]");
    if (!openButton || !modal) return;
    var closeButtons = modal.querySelectorAll("[data-queue-overview-close]");
    var closeButton = modal.querySelector(".af-queue-modal__close");
    function openModal() {
        modal.hidden = false;
        document.body.classList.add("af-modal-open");
        openButton.setAttribute("aria-expanded", "true");
        if (closeButton) closeButton.focus();
    }
    function closeModal() {
        modal.hidden = true;
        document.body.classList.remove("af-modal-open");
        openButton.setAttribute("aria-expanded", "false");
        openButton.focus();
    }
    openButton.setAttribute("aria-haspopup", "dialog");
    openButton.setAttribute("aria-expanded", "false");
    openButton.addEventListener("click", openModal);
    closeButtons.forEach(function (button) { button.addEventListener("click", closeModal); });
    document.addEventListener("keydown", function (event) { if (event.key === "Escape" && !modal.hidden) closeModal(); });
}());

// Inline personal-information editor. Identity and role remain read-only.
(function () {
    var form = document.querySelector("[data-profile-edit-form]");
    if (!form) return;
    var view = document.querySelector(".af-about-me-view");
    document.querySelectorAll("[data-profile-edit-open]").forEach(function (button) {
        button.addEventListener("click", function () { form.hidden = false; if (view) view.hidden = true; var input = form.querySelector("input"); if (input) input.focus(); });
    });
    var cancel = form.querySelector("[data-profile-edit-cancel]");
    if (cancel) cancel.addEventListener("click", function () { form.hidden = true; if (view) view.hidden = false; });
}());

// Incident assistant suggestion buttons populate the real question form.
document.querySelectorAll("[data-question-suggestion]").forEach(function (button) {
    button.addEventListener("click", function () {
        var input = document.querySelector("[data-incident-question]");
        if (input) { input.value = button.textContent.trim(); input.focus(); }
    });
});

// In-flight state for every AI-triggering form (marked data-ai-action):
// on submit, show a spinner on the clicked button and disable every
// submit control in the form so an impatient second click can't fire a
// second (billed) request. A full-page POST/redirect follows, so the
// next render resets everything; pageshow handles the bfcache Back case.
(function () {
    var SPINNER = '<span class="ai-inflight-spinner" aria-hidden="true"></span><span>Working…</span>';

    function submitControls(form) {
        return Array.prototype.slice.call(
            form.querySelectorAll('button, input[type="submit"], input[type="image"]')
        ).filter(function (el) {
            var type = (el.getAttribute("type") || "submit").toLowerCase();
            return el.tagName === "INPUT" ? (type === "submit" || type === "image") : type !== "button";
        });
    }

    function lock(form, submitter) {
        submitControls(form).forEach(function (btn) {
            if (btn === submitter && btn.tagName === "BUTTON") {
                btn.dataset.aiOriginalHtml = btn.innerHTML;
                btn.innerHTML = SPINNER;
                btn.classList.add("is-ai-loading");
            } else {
                btn.classList.add("is-ai-disabled");
            }
        });
        // Disable on the next tick: the browser has already captured the
        // submitter (and its name/value) for this submission by now, so
        // disabling doesn't drop it, but a second click is blocked.
        setTimeout(function () {
            submitControls(form).forEach(function (btn) { btn.disabled = true; });
        }, 0);
    }

    function unlock(form) {
        delete form.dataset.aiSubmitting;
        submitControls(form).forEach(function (btn) {
            btn.disabled = false;
            btn.classList.remove("is-ai-disabled");
            if (btn.classList.contains("is-ai-loading")) {
                btn.classList.remove("is-ai-loading");
                if (typeof btn.dataset.aiOriginalHtml === "string") {
                    btn.innerHTML = btn.dataset.aiOriginalHtml;
                    delete btn.dataset.aiOriginalHtml;
                }
            }
        });
    }

    document.addEventListener("submit", function (event) {
        var form = event.target;
        if (!form || !form.matches || !form.matches("form[data-ai-action]")) return;
        if (form.dataset.aiSubmitting === "1") { event.preventDefault(); return; }
        form.dataset.aiSubmitting = "1";
        lock(form, event.submitter || null);
    }, true);

    // Back/forward cache can restore the page with buttons still locked.
    window.addEventListener("pageshow", function (event) {
        if (!event.persisted) return;
        document.querySelectorAll('form[data-ai-action]').forEach(unlock);
    });
}());

// Settings appearance buttons share the exact theme state used by the topbar.
(function () {
    var root = document.documentElement;
    var choices = document.querySelectorAll("[data-theme-choice]");
    if (!choices.length) return;
    function sync() { choices.forEach(function (button) { button.classList.toggle("is-active", button.dataset.themeChoice === root.dataset.theme); }); }
    choices.forEach(function (button) { button.addEventListener("click", function () {
        if (root.dataset.theme !== button.dataset.themeChoice) {
            var toggle = document.querySelector("[data-theme-toggle]");
            if (toggle) toggle.click();
        }
        sync();
    }); });
    new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
    sync();
}());

// Global Aegis drawer. Pinning only affects dismissal; questions still use the real app assistant POST.
(function () {
    var drawer = document.querySelector("[data-aegis-drawer]");
    var overlay = document.querySelector("[data-aegis-overlay]");
    if (!drawer || !overlay) return;
    var openButtons = document.querySelectorAll("[data-aegis-open]");
    var closeButton = drawer.querySelector("[data-aegis-close]");
    var pinButton = drawer.querySelector("[data-aegis-pin]");
    var input = drawer.querySelector("[data-aegis-input]");
    var pinned = false;
    var returnFocus = null;

    function openDrawer(trigger) {
        returnFocus = trigger || document.activeElement;
        drawer.classList.add("is-open");
        drawer.setAttribute("aria-hidden", "false");
        overlay.hidden = pinned;
        document.body.classList.add("af-aegis-open");
        window.setTimeout(function () { if (input) input.focus(); }, 0);
    }
    function closeDrawer() {
        drawer.classList.remove("is-open");
        drawer.setAttribute("aria-hidden", "true");
        overlay.hidden = true;
        document.body.classList.remove("af-aegis-open");
        if (returnFocus && returnFocus.focus) returnFocus.focus();
    }
    function syncPin() {
        pinButton.setAttribute("aria-pressed", pinned ? "true" : "false");
        pinButton.setAttribute("title", pinned ? "Unpin drawer" : "Pin drawer");
        pinButton.setAttribute("aria-label", pinned ? "Unpin drawer" : "Pin drawer");
        pinButton.setAttribute("data-tooltip", pinned ? "Unpin drawer" : "Pin drawer");
        if (drawer.classList.contains("is-open")) overlay.hidden = pinned;
    }
    openButtons.forEach(function (button) { button.addEventListener("click", function () { openDrawer(button); }); });
    closeButton.addEventListener("click", closeDrawer);
    overlay.addEventListener("click", function () { if (!pinned) closeDrawer(); });
    pinButton.addEventListener("click", function () { pinned = !pinned; syncPin(); });
    drawer.querySelectorAll("[data-aegis-suggestion]").forEach(function (button) {
        button.addEventListener("click", function () { if (input) { input.value = button.textContent.trim(); input.focus(); } });
    });
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && drawer.classList.contains("is-open") && !pinned) closeDrawer();
    });
    syncPin();
}());

// Shared active Aegis conversation for drawer and full-page views.
(function(){var scope=document.body.dataset.aegisScope||"anonymous",KEY="aegisflow.activeChat.v1."+scope,sending=false,forms=document.querySelectorAll("[data-aegis-chat-form]"),drawerMessages=document.querySelector("[data-aegis-messages]"),fullMessages=document.querySelector("[data-aegis-messages-full]"),suggestions=document.querySelector("[data-aegis-suggestions]"),historyList=document.querySelector("[data-aegis-history-list]");if(!forms.length)return;function uid(){return(window.crypto&&crypto.randomUUID)?crypto.randomUUID():String(Date.now())+Math.random().toString(16).slice(2)}function pageContext(){var title=document.querySelector("[data-aegis-page-title]");return title?title.textContent.trim():(document.title||"AegisFlow")}function load(){try{var value=JSON.parse(localStorage.getItem(KEY));if(value&&value.activeId&&Array.isArray(value.conversations))return value}catch(error){}var id=uid();return{activeId:id,conversations:[{id:id,title:"New chat",context:pageContext(),createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),messages:[]}]}}var state=load();var serverItems=document.querySelectorAll("[data-aegis-server-thread] article");if(serverItems.length&&state.conversations.every(function(chat){return !chat.messages.length})){var seeded=state.conversations[0];seeded.title=serverItems[0].dataset.question.slice(0,52);seeded.context="Saved Aegis conversation";seeded.messages=[];serverItems.forEach(function(item){seeded.messages.push({role:"user",text:item.dataset.question,at:item.dataset.askedAt});seeded.messages.push({role:"assistant",text:item.dataset.answer,at:item.dataset.askedAt})});seeded.updatedAt=serverItems[serverItems.length-1].dataset.askedAt||new Date().toISOString()}function active(){var found=state.conversations.find(function(chat){return chat.id===state.activeId});if(!found){found={id:uid(),title:"New chat",context:pageContext(),createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),messages:[]};state.conversations.push(found);state.activeId=found.id}return found}function save(){localStorage.setItem(KEY,JSON.stringify(state))}function addMessage(role,text,status){var chat=active();chat.messages.push({role:role,text:text,status:status||"",at:new Date().toISOString()});if(role==="user"&&chat.title==="New chat")chat.title=text.slice(0,52);chat.updatedAt=new Date().toISOString();save()}function messageNode(message){var row=document.createElement("article");row.className="af-aegis-chat-message af-aegis-chat-message--"+message.role+(message.status?" is-"+message.status:"");var label=document.createElement("strong");label.textContent=message.role==="user"?"You":"Aegis";var copy=document.createElement("p");copy.textContent=message.text;row.appendChild(label);row.appendChild(copy);if(message.status==="error"){var retry=document.createElement("button");retry.type="button";retry.textContent="Try again";retry.setAttribute("data-aegis-retry","");row.appendChild(retry)}return row}function renderMessages(target){if(!target)return;target.innerHTML="";var messages=active().messages;if(!messages.length){var empty=document.createElement("div");empty.className="af-aegis-chat-empty";empty.innerHTML="<strong>How can I help?</strong><p>Ask Aegis a question to start this chat.</p>";target.appendChild(empty)}else messages.forEach(function(message){target.appendChild(messageNode(message))});if(sending){var thinking=document.createElement("article");thinking.className="af-aegis-chat-message af-aegis-chat-message--assistant is-thinking";thinking.innerHTML="<strong>Aegis</strong><p>Aegis is thinking…</p>";target.appendChild(thinking)}target.scrollTop=target.scrollHeight}function renderHistory(){if(!historyList)return;historyList.innerHTML="";state.conversations.slice().sort(function(a,b){return new Date(b.updatedAt)-new Date(a.updatedAt)}).forEach(function(chat){var button=document.createElement("button");button.type="button";button.className=chat.id===state.activeId?"is-active":"";button.innerHTML="<strong></strong><time></time>";button.querySelector("strong").textContent=chat.title;button.querySelector("time").textContent=new Date(chat.updatedAt).toLocaleString([],{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"});button.addEventListener("click",function(){state.activeId=chat.id;save();render()});historyList.appendChild(button)})}function render(){renderMessages(drawerMessages);renderMessages(fullMessages);if(suggestions)suggestions.classList.toggle("is-compact",active().messages.length>1);renderHistory();forms.forEach(function(form){var input=form.querySelector("input[name=question]"),button=form.querySelector("button[type=submit],button:not([type])");if(input)input.disabled=sending;if(button)button.disabled=sending})}function send(form,forcedQuestion,skipUser){if(sending)return;var input=form.querySelector("input[name=question]"),question=(forcedQuestion||(input&&input.value)||"").trim();if(!question)return;if(input)input.value="";if(!skipUser)addMessage("user",question);sending=true;render();var data=new FormData(form);data.set("question",question);fetch(form.action,{method:"POST",body:data,headers:{"X-Requested-With":"XMLHttpRequest"},credentials:"same-origin"}).then(function(response){return response.json().then(function(body){if(!response.ok)throw new Error(body.error||"Aegis could not complete that request.");return body})}).then(function(body){addMessage("assistant",body.answer)}).catch(function(error){addMessage("assistant",error.message||"Aegis could not complete that request.","error")}).finally(function(){sending=false;render();if(input)input.focus()})}forms.forEach(function(form){form.addEventListener("submit",function(event){event.preventDefault();send(form)})});document.querySelectorAll("[data-aegis-suggestion]").forEach(function(button){button.addEventListener("click",function(){var form=document.querySelector(".af-aegis-drawer [data-aegis-chat-form]")||forms[0];send(form,button.textContent.trim())})});document.querySelectorAll("[data-aegis-new-chat]").forEach(function(button){button.addEventListener("click",function(){var id=uid();state.activeId=id;state.conversations.push({id:id,title:"New chat",context:pageContext(),createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),messages:[]});save();render();var input=document.querySelector(".af-aegis-drawer [data-aegis-input]")||document.querySelector("[data-aegis-chat-form] input");if(input)input.focus()})});document.addEventListener("click",function(event){var retry=event.target.closest("[data-aegis-retry]");if(!retry)return;var chat=active(),last=[].concat(chat.messages).reverse().find(function(message){return message.role==="user"});chat.messages=chat.messages.filter(function(message){return message.status!=="error"});save();if(last)send(forms[0],last.text,true)});window.addEventListener("storage",function(event){if(event.key===KEY){state=load();render()}});save();render()}());
