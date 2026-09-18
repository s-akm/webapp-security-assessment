package com.example;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<User> list() { return repo.findAll(); }
}
