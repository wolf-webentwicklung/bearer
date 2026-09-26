const { exec, execSync } = require("child_process");

function ping(host) {
  exec("ping -c 1 " + host, (err, out) => console.log(out));
}

function list(dir) {
  return execSync(`ls ${dir}`).toString();
}

function calc(expr) {
  return eval(expr);
}

function make(body) {
  return new Function("a", body);
}

ping(process.argv[2]);
list(process.argv[3]);
calc(process.argv[4]);
make(process.argv[5]);
