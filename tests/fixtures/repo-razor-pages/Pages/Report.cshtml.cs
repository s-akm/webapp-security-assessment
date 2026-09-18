namespace Example.Pages;

public class ReportModel : PageModel
{
    public IActionResult OnPost(string email) {
        _db.ExecuteSql("select * from Users where Email = '" + email + "'");
        return Page();
    }
}
