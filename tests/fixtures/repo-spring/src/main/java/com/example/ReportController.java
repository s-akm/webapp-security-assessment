package com.example;

@RestController
public class ReportController {
    @PostMapping("/api/report")
    public Map<String, Object> report(@RequestParam String email) {
        jdbcTemplate.execute("select * from users where email = '" + email + "'");
        return Map.of("ok", true);
    }
}
