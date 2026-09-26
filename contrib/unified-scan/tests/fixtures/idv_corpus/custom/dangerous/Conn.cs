using System.Data.SqlClient;

class Conn {
    static SqlConnection Open() {
        var c = new SqlConnection("Server=db01;Database=report;User Id=report;Password=Sommer2026!;");
        c.Open();
        return c;
    }
}
