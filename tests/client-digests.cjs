// SPDX-License-Identifier: AGPL-3.0-only
const {readFileSync} = require("node:fs");
const client = require(process.argv[2]);

async function main() {
  const rows = JSON.parse(readFileSync(0, "utf8"));
  const results = [];
  for (const row of rows) {
    try {
      if (row.number) row.payload.workflow.steps[1].condition_value = Number(row.number);
      if (row.sparse) delete row.payload.dependencies[0];
      if (row.sparseNested) delete row.payload.workflow.steps[1].dependencies[0];
      const result = {digest: await client[row.helper](row.payload)};
      if (row.wire) result.wire = JSON.stringify(row.payload);
      results.push(result);
    }
    catch (error) { results.push({error: error.message}); }
  }
  process.stdout.write(JSON.stringify(results));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
