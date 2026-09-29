var group = app.MapGroup("/api"); group.MapGet("/users", () => Results.Ok());
