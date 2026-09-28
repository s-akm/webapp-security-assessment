class InvoiceController {
    @GetMapping("/invoices")
    List<Invoice> list(@RequestParam(value = "pageSize", defaultValue = "20") int pageSize) {
        return repo.findAll(PageRequest.of(0, pageSize)).getContent();
    }
}
