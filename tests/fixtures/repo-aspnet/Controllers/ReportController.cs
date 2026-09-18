namespace Example.Controllers;

[ApiController]
[Route("api/report")]
public class ReportController : ControllerBase
{
    [HttpPost]
    public IActionResult Post(string email) {
        _db.ExecuteSql("select * from Users where Email = '" + email + "'");
        return Ok();
    }
}
