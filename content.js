// A basic regex array to detect common XSS patterns
const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/i, // <script>alert(1)</script>
  /javascript:/i, // javascript:alert(1)
  /onerror\s*=/i, // <img src=x onerror=alert(1)>
  /onload\s*=/i, // <body onload=alert(1)>
  /onclick\s*=/i, // Any malicious inline click handlers
  /onbeforeprint\s*=/i, // <body onbeforeprint=alert(1)>
  /\bon[a-z]+\s*=/i,
];

function scanForXSS(event) {
  const inputValue = event.target.value;

  for (let pattern of XSS_PATTERNS) {
    if (pattern.test(inputValue)) {
      // Highlight the field in red as a warning
      event.target.style.border = "3px solid red";
      event.target.style.backgroundColor = "#ffe6e6";

      console.warn(
        "⚠️ Potential XSS Attack Script Detected in field:",
        event.target,
      );
      return; // Stop checking once a match is found
    }
  }

  // Reset styles if the input becomes safe again
  event.target.style.border = "";
  event.target.style.backgroundColor = "";
}

// Listen for typing (input) and pasting in the document
// document.addEventListener("input", function (event) {
//   const tagName = event.target.tagName.toLowerCase();
//   if (tagName === "input" || tagName === "textarea") {
//     scanForXSS(event);
//   }
// });

// This listens to the entire page and catches events from ANY input dynamically
document.addEventListener("input", function (event) {
  const target = event.target;
  // Handle standard elements or elements inside shadow DOMs (common on YouTube)
  if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) {
    scanForXSS(event);
  }
});
