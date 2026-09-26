const { exec } = require("child_process");
const host = process.argv[2];
exec("ping -c 1 " + host, (err, out) => console.log(out));
eval(process.argv[3]);
