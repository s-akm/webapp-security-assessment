[ApiController]
public class OrdersController : ControllerBase
{
    [HttpGet("orders")]
    [Authorize]
    public IActionResult List() => Ok();

    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult Public() => Ok();

    [HttpPost("orders")]
    public IActionResult Create() => Ok();
}
