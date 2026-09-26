import java.nio.file.*;
import java.util.*;

public class Report {
    public static void main(String[] args) throws Exception {
        Path in = Paths.get(args[0]);
        List<String> lines = Files.readAllLines(in);
        System.out.println("rows: " + lines.size());
        Files.write(Paths.get(args[1]), lines);
    }
}
