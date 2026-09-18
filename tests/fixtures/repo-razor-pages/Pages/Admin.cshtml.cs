namespace Example.Pages;

[Authorize(Roles = "Admin")]
public class AdminModel : PageModel
{
    public void OnGet() { }
}
