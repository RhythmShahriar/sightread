// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

(function () {
  "use strict";
  // Sort the update table by a column; the cell's data-v holds the key.
  document.querySelectorAll("table.sortable th[data-col]").forEach(function (th) {
    th.addEventListener("click", function () {
      var table = th.closest("table"), body = table.tBodies[0], col = +th.dataset.col;
      var asc = th.getAttribute("aria-sort") !== "ascending";
      table.querySelectorAll("th[data-col]").forEach(function (o) { o.removeAttribute("aria-sort"); });
      th.setAttribute("aria-sort", asc ? "ascending" : "descending");
      var rows = Array.prototype.slice.call(body.rows);
      rows.sort(function (a, b) {
        var x = a.cells[col].dataset.v || a.cells[col].textContent, y = b.cells[col].dataset.v || b.cells[col].textContent;
        var c = x.localeCompare(y, undefined, { numeric: true });
        return asc ? c : -c;
      });
      rows.forEach(function (r) { body.appendChild(r); });
    });
  });

  // Copy a hash or a command.
  document.querySelectorAll("button[data-copy]").forEach(function (b) {
    b.addEventListener("click", function () {
      if (!navigator.clipboard) { return; }
      navigator.clipboard.writeText(b.dataset.copy).then(function () {
        b.textContent = "copied";
        setTimeout(function () { b.textContent = "copy"; }, 1500);
      });
    });
  });

  // Side by side: built once from the unified rows, text only.
  function cell(tr, cls, text) {
    var td = document.createElement("td");
    td.className = cls;
    td.textContent = text;
    tr.appendChild(td);
  }
  function split(table) {
    var out = document.createElement("table"), body = document.createElement("tbody");
    out.className = "diff split";
    var dels = [], adds = [];
    function flush() {
      for (var i = 0; i < Math.max(dels.length, adds.length); i++) {
        var tr = document.createElement("tr"), d = dels[i], a = adds[i];
        cell(tr, "ln", d ? d.cells[0].textContent : "");
        cell(tr, d ? "code del" : "code", d ? d.cells[2].textContent : "");
        cell(tr, "ln", a ? a.cells[1].textContent : "");
        cell(tr, a ? "code add" : "code", a ? a.cells[2].textContent : "");
        body.appendChild(tr);
      }
      dels = []; adds = [];
    }
    Array.prototype.forEach.call(table.tBodies[0].rows, function (r) {
      var k = r.dataset.k;
      if (k === "-") { if (adds.length) { flush(); } dels.push(r); return; }
      if (k === "+") { adds.push(r); return; }
      flush();
      var tr = document.createElement("tr"), cls = "code " + (k === "@" ? "hunk" : k === "\\" ? "note" : "");
      cell(tr, "ln", r.cells[0].textContent);
      cell(tr, cls, r.cells[2].textContent);
      cell(tr, "ln", r.cells[1].textContent);
      cell(tr, cls, r.cells[2].textContent);
      body.appendChild(tr);
    });
    flush();
    out.appendChild(body);
    table.parentNode.insertBefore(out, table.nextSibling);
  }
  var toggle = document.getElementById("view");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var side = !document.body.classList.contains("side");
      if (side) {
        document.querySelectorAll("table.diff.unified").forEach(function (t) {
          if (!t.nextElementSibling || !t.nextElementSibling.classList.contains("split")) { split(t); }
        });
      }
      document.body.classList.toggle("side", side);
      toggle.textContent = side ? "Show unified" : "Show side by side";
    });
  }
})();
