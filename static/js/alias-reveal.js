/* Sensitive-identifier click-to-reveal (Part 6 of the alias overhaul).
 *
 * Every {% alias_field %} / {% alias_prose %} value renders as
 *   <span class="af-alias" data-alias-pk="N" data-alias-label="[HOST_003]">
 *     <span class="af-alias__value">[HOST_003]</span>
 *     <button class="af-alias__toggle">…eye…</button>
 *   </span>
 * This script is included once by every base layout. One delegated click
 * handler covers every alias on the page, including any added after load.
 *
 * Toggle behaviour: first click POSTs to ai_core:reveal_alias and swaps the
 * visible text to the real value; clicking again restores the alias label and
 * DISCARDS the fetched value (it is never cached -- a re-reveal re-fetches, so
 * every reveal is a fresh, individually audited request).
 */
(function () {
  "use strict";

  var form = document.querySelector(".af-alias-reveal");
  if (!form) {
    return;
  }

  function csrfToken() {
    var field = form.querySelector('input[name="csrfmiddlewaretoken"]');
    return field ? field.value : "";
  }

  function revealUrl(pk) {
    // data-reveal-url is ".../ai/reveal/0/" (reversed with a placeholder pk).
    return (form.dataset.revealUrl || "").replace(/0\/$/, encodeURIComponent(pk) + "/");
  }

  function hide(wrap, valueEl, toggle) {
    valueEl.textContent = wrap.dataset.aliasLabel;
    wrap.classList.remove("is-revealed");
    toggle.setAttribute("aria-label", "Reveal the real value behind " + wrap.dataset.aliasLabel);
  }

  function reveal(wrap, valueEl, toggle) {
    var pk = wrap.dataset.aliasPk;
    if (!pk || wrap.classList.contains("is-loading")) {
      return;
    }
    wrap.classList.remove("is-error");
    wrap.classList.add("is-loading");
    fetch(revealUrl(pk), {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "X-CSRFToken": csrfToken(),
        "X-Requested-With": "XMLHttpRequest"
      }
    })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("reveal failed (" + response.status + ")");
        }
        return response.json();
      })
      .then(function (data) {
        valueEl.textContent = data.real_value;
        wrap.classList.add("is-revealed");
        toggle.setAttribute("aria-label", "Hide " + wrap.dataset.aliasLabel + " again");
      })
      .catch(function () {
        wrap.classList.add("is-error");
      })
      .then(function () {
        wrap.classList.remove("is-loading");
      });
  }

  document.addEventListener("click", function (event) {
    var toggle = event.target.closest(".af-alias__toggle");
    if (!toggle) {
      return;
    }
    var wrap = toggle.closest(".af-alias");
    var valueEl = wrap && wrap.querySelector(".af-alias__value");
    if (!wrap || !valueEl) {
      return;
    }
    event.preventDefault();
    if (wrap.classList.contains("is-revealed")) {
      hide(wrap, valueEl, toggle);
    } else {
      reveal(wrap, valueEl, toggle);
    }
  });
})();
