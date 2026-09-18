package com.example;

@Controller("/api/report")
public class ReportController {
    @Post
    public HttpResponse<?> create(@QueryValue String email) {
        em.createNativeQuery("select * from users where email = '" + email + "'");
        return HttpResponse.ok();
    }
}
