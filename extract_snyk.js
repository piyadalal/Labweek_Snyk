const { execSync } = require("child_process");

function run(command) {
  return execSync(command, { stdio: "inherit" });
}

try {
  console.log("🔍 Checking Snyk installation...");
  execSync("snyk --version", { stdio: "ignore" });
} catch {
  console.log("⬇ Installing Snyk CLI...");
  run("npm install -g snyk");
}

try {
  console.log("🔐 Checking Snyk authentication...");
  execSync("snyk auth --check", { stdio: "ignore" });
} catch {
  console.log("🔑 Authenticating Snyk...");
  run("snyk auth");
}

console.log("📦 Exporting Snyk issues...");
run("snyk test --json > snyk-results.json");

console.log("✅ Done. Results saved to snyk-results.json");