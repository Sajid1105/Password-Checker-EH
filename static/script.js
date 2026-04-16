let timeout = null;

// REAL-TIME typing
document.getElementById("password").addEventListener("input", () => {
    clearTimeout(timeout);
    timeout = setTimeout(() => {
        checkPassword();
    }, 400);
});

async function checkPassword() {
    const password = document.getElementById("password").value;
    if (!password) return;

    const res = await fetch("/analyze", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ password })
    });

    const data = await res.json();

    displayResult(data);
    updateStrength(data.strength);
}

// Display results
function displayResult(data) {
    const resultDiv = document.getElementById("result");

    let breachWarning = "";

    if (data.breach_count > 0) {
        breachWarning = `
            <div class="breach-alert">
                ⚠️ This password has appeared in data breaches (${data.breach_count} times)!
            </div>
        `;
    }

    resultDiv.innerHTML = `
        ${breachWarning}

        <p><strong>Strength:</strong> ${data.strength}/4</p>

        <h3>Attack Simulation:</h3>
        <p>Guesses: ${data.guesses || "N/A"}</p>
        <h3>Attack Simulation:</h3>
<p><strong>Fast Attack (GPU):</strong> ${data.crack_time_fast}</p>
<p><strong>Realistic Attack (bcrypt):</strong> ${data.crack_time_slow}</p>

        <h3>Issues:</h3>
        <ul>
            ${data.issues.map(i => `<li>${i}</li>`).join("")}
        </ul>

        <h3>Suggestions:</h3>
        <ul>
            ${data.suggestions.map(s => `<li>${s}</li>`).join("")}
        </ul>
    `;
}

// Strength bar
function updateStrength(score) {
    const bar = document.getElementById("strength-bar");

    const colors = ["red", "orange", "yellow", "lightgreen", "green"];
    bar.style.width = (score + 1) * 20 + "%";
    bar.style.background = colors[score];
}

// Generate password
async function generatePassword() {
    const res = await fetch("/generate");
    const data = await res.text();

    document.getElementById("password").value = data;

    document.getElementById("generator-info").innerHTML = `
        <p>Generated using:</p>
        <ul>
            <li>✔ Uppercase + Lowercase</li>
            <li>✔ Numbers</li>
            <li>✔ Special Characters</li>
            <li>✔ Length > 12</li>
        </ul>
    `;
}

// Copy to clipboard
function copyPassword() {
    const password = document.getElementById("password").value;

    if (!password) {
        alert("Nothing to copy!");
        return;
    }

    navigator.clipboard.writeText(password);
    alert("Copied to clipboard!");
}

// Toggle visibility
function toggle() {
    const input = document.getElementById("password");
    input.type = input.type === "password" ? "text" : "password";
}