const fs = require("fs");
const path = require("path");

function summarize(file) {
  const lines = fs.readFileSync(file, "utf8").split("\n").slice(1);
  let total = 0;
  for (const l of lines) {
    const parts = l.split(";");
    total += Number(parts[2] || 0);
  }
  return total;
}

const input = process.argv[2];
const out = path.join(path.dirname(input), "summary.txt");
fs.writeFileSync(out, String(summarize(input)));
console.log("written", out);
