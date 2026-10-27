"use strict";
/* global _post:readable, BASE_URL:readable */

// Keykeeper: approving a shared site fix on the Sites page, or taking the
// approval back (SITE_FIXES_NEED_APPROVAL).
function setApproval(event) {
    event.preventDefault();
    const id = event.target.parentNode.dataset.vwSiteFix;
    const approved = event.target.getAttribute("vw-site-fix-approve") === "true";
    if (!id) {
        alert("Required parameters not found!");
        return;
    }
    _post(`${BASE_URL}/admin/sites/fixes/${id}/approval`,
        approved ? "Approved" : "Approval taken back",
        "Error saving the approval",
        JSON.stringify({ approved })
    );
}

document.addEventListener("DOMContentLoaded", (/*event*/) => {
    document.querySelectorAll("button[vw-site-fix-approve]").forEach(btn => {
        btn.addEventListener("click", setApproval);
    });
});
