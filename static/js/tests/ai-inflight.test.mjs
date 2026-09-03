/**
 * Behavioural test for the AI-form in-flight guard added to
 * static/js/dashboard.js (Part G, item 1, fix 2): the FIRST submit of a
 * [data-ai-action] form goes through and locks the form; a SECOND submit
 * while that request is still in flight is cancelled -- so an impatient
 * double-click can never fire two billed Claude calls.
 *
 * Run: node --test static/js/tests/
 * No DOM library: a tiny hand-rolled shim is enough for this IIFE.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(here, "..", "dashboard.js"), "utf8");

// Pull out just the "In-flight state ..." IIFE.
const start = src.indexOf("// In-flight state for every AI-triggering form");
const END = "}());";
const end = src.indexOf(END, start) + END.length;
const iife = src.slice(start, end);
assert.ok(start !== -1 && iife.includes("data-ai-action"), "located the in-flight IIFE");

function classList() {
    const set = new Set();
    return {
        add: (c) => set.add(c),
        remove: (c) => set.delete(c),
        contains: (c) => set.has(c),
    };
}

function makeButton({ tag = "BUTTON", type = "submit" } = {}) {
    return {
        tagName: tag,
        _attrs: { type },
        getAttribute(name) { return name in this._attrs ? this._attrs[name] : null; },
        dataset: {},
        innerHTML: "Ask",
        classList: classList(),
        disabled: false,
    };
}

function makeForm(buttons, { aiAction = true } = {}) {
    return {
        dataset: {},
        matches(sel) { return sel === "form[data-ai-action]" ? aiAction : false; },
        querySelectorAll() { return buttons.slice(); },
    };
}

// --- load the IIFE against a fake document/window ---------------------
let submitHandler = null;
const pendingTimeouts = [];

const documentShim = {
    addEventListener(type, fn) { if (type === "submit") submitHandler = fn; },
    querySelectorAll() { return []; },
};
const windowShim = { addEventListener() {} };
const setTimeoutShim = (fn) => { pendingTimeouts.push(fn); return pendingTimeouts.length; };

// eslint-disable-next-line no-new-func
new Function("document", "window", "setTimeout", iife)(documentShim, windowShim, setTimeoutShim);
assert.equal(typeof submitHandler, "function", "IIFE registered a submit handler");

function flushTimers() {
    while (pendingTimeouts.length) pendingTimeouts.shift()();
}

test("first submit is allowed and locks the form; second submit is blocked", () => {
    const primary = makeButton();
    const other = makeButton();
    const form = makeForm([primary, other]);

    let prevented = 0;
    submitHandler({ target: form, submitter: primary, preventDefault: () => { prevented += 1; } });

    assert.equal(prevented, 0, "the first submit reaches the server");
    assert.equal(form.dataset.aiSubmitting, "1");
    assert.ok(primary.classList.contains("is-ai-loading"), "clicked button shows loading state");
    assert.ok(primary.innerHTML.includes("ai-inflight-spinner"), "clicked button shows a spinner");
    assert.ok(other.classList.contains("is-ai-disabled"), "sibling submit buttons are disabled too");

    // Disable happens on the next tick (after the browser captured the submitter).
    assert.equal(primary.disabled, false);
    flushTimers();
    assert.equal(primary.disabled, true);
    assert.equal(other.disabled, true);

    // The impatient second click while the request is still in flight.
    submitHandler({ target: form, submitter: primary, preventDefault: () => { prevented += 1; } });
    assert.equal(prevented, 1, "the second submit is cancelled -> no duplicate billed call");
});

test("a plain (non data-ai-action) form is untouched", () => {
    const btn = makeButton();
    const form = makeForm([btn], { aiAction: false });

    let prevented = 0;
    submitHandler({ target: form, submitter: btn, preventDefault: () => { prevented += 1; } });

    assert.equal(prevented, 0);
    assert.equal(form.dataset.aiSubmitting, undefined);
    assert.equal(btn.classList.contains("is-ai-loading"), false);
});

test("type=button controls are never disabled by the guard", () => {
    const realSubmit = makeButton();
    const plainButton = makeButton({ type: "button" });
    const form = makeForm([realSubmit, plainButton]);

    submitHandler({ target: form, submitter: realSubmit, preventDefault: () => {} });
    flushTimers();

    assert.equal(realSubmit.disabled, true);
    assert.equal(plainButton.disabled, false, "a type=button control stays clickable");
});
