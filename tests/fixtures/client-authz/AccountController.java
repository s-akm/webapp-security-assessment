@PostMapping("/accounts")
public Account create(@RequestParam("role") String role, @RequestBody AccountForm form) {
    return service.create(form, role);
}
