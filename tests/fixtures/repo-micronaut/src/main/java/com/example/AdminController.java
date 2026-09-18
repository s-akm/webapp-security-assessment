package com.example;

@Controller("/api/admin")
@Secured(SecurityRule.IS_AUTHENTICATED)
public class AdminController {
    @Get
    public List<User> list() { return repo.findAll(); }
}
