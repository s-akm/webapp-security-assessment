@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/users")
    public List<User> users() { return null; }
}
