package com.example;

@Path("/api/admin")
public class AdminResource {
    @GET
    @RolesAllowed("admin")
    public List<User> list() { return repo.listAll(); }
}
