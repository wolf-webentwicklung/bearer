const { exec, execSync, execFile } = require("child_process");

exec("git status", (err, out) => console.log(out));
const v = execSync("node --version").toString();
execFile("ping", ["-c", "1", process.argv[2]], () => {});
const total = eval("1 + 2");
console.log(v, total);
