using System;
using System.Data.SqlClient;

class ConnEnv {
    static SqlConnection Open() {
        var pw = Environment.GetEnvironmentVariable("DB_PASSWORD");
        return new SqlConnection($"Server=db01;Database=report;User Id=report;Password={pw};");
    }
}
