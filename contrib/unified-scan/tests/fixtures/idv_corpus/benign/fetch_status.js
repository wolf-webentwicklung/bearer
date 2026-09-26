async function main() {
  const res = await fetch("https://intranet.example.internal/api/status");
  const data = await res.json();
  console.log(data.status);
}
main();
