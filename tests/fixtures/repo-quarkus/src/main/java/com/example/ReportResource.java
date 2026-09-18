package com.example;

@Path("/api/report")
public class ReportResource {
    @POST
    public Response create(@QueryParam("email") String email) {
        em.createNativeQuery("select * from users where email = '" + email + "'");
        return Response.ok().build();
    }
}
