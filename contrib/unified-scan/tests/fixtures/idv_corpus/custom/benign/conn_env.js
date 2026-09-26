const sql = require("mssql");
const config = `Server=db01;Database=report;User Id=report;Password=${process.env.DB_PASSWORD}`;
sql.connect(config);
