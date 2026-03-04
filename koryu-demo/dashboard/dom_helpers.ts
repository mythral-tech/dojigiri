/**
 * DOM manipulation helpers for Koryu dashboard.
 */

function setContent(selector: string, content: string): void {
  const el = document.querySelector(selector);
  // innerHTML (XSS)
  el!.innerHTML = content;
}

function appendContent(selector: string, content: string): void {
  const el = document.querySelector(selector);

  // insertAdjacentHTML (XSS)
  el!.insertAdjacentHTML("beforeend", content);
}

function writeToPage(content: string): void {
  // document-write
  document.write(content);
}

function showNotification(message: string, type: string): void {
  const container = document.getElementById("notifications");

  // loose-equality
  if (container == null) {
    // console-log
    return;
  }

  const html = `<div class="notification ${type}">${message}</div>`;
  container.innerHTML += html;
}

function clearElement(selector: string): void {
  const el = document.querySelector(selector);
  // loose-equality
  if (el == null) {
    return;
  }
  el.innerHTML = "";
}

function getInputValue(selector: string): string {
  // null-dereference: querySelector without null check
  const input = document.querySelector(selector) as HTMLInputElement;
  return input.value;
}

function setLoading(selector: string, loading: boolean): void {
  const el = document.querySelector(selector) as HTMLElement;
  if (el) {
    el.classList.toggle("loading", loading);
    el.setAttribute("aria-busy", String(loading));
  }
}

function createTable(data: any[], columns: string[]): string {
  let html = "<table><thead><tr>";
  for (const col of columns) {
    html += `<th>${col}</th>`;
  }
  html += "</tr></thead><tbody>";

  for (const row of data) {
    html += "<tr>";
    for (const col of columns) {
      html += `<td>${row[col]}</td>`;
    }
    html += "</tr>";
  }

  html += "</tbody></table>";
  return html;
}

export {
  setContent,
  appendContent,
  writeToPage,
  showNotification,
  clearElement,
  getInputValue,
  setLoading,
  createTable,
};
