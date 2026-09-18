var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/api/admin", () => Results.Ok()).RequireAuthorization();
app.MapPost("/api/report", (string email) => {
    _db.ExecuteSql("select * from Users where Email = '" + email + "'");
    return Results.Ok();
});
app.Run();
